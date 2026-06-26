import { X509Certificate, verify as cryptoVerify, createHash } from 'crypto';
import { connect as tlsConnect } from 'tls';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir, tmpdir } from 'os';
import type { IExecuteFunctions } from 'n8n-workflow';

const KDS_DOMAIN = 'kdsintf.amd.com';

// Known-good launch measurements per nilCC artifacts version, each verified once
// against Nillion's official nilcc-verifier. If the live enclave reports a
// measurement that matches, we know it's running a build we've audited. Extend
// this map as nilAI's deployment is upgraded (ideally Nillion publishes these).
const KNOWN_MEASUREMENTS: Record<string, string> = {
	'0.3.0': '981bcaa62bcd63cb03c7b93a67d1a8c17ff63e45e6d16323a8784bacbfcb254313741bcf32d0bccc795d6ea0e6ac1481',
};

// AMD certs are stable per chip/TCB, so cache them across executions (in-memory).
// Keyed by processor — Milan/Genoa/Turin each have their own chain.
const certChainCache: Record<string, { ark: X509Certificate; ask: X509Certificate }> = {};
const vcekCache: Record<string, X509Certificate> = {};

// ...and on disk, so we don't re-fetch from AMD's (heavily rate-limited) KDS on
// every cold start. Fails over gracefully if the filesystem isn't writable.
function certCacheDir(): string {
	for (const base of [join(homedir(), '.n8n'), tmpdir()]) {
		try {
			const dir = join(base, '.nilai-cert-cache');
			mkdirSync(dir, { recursive: true });
			return dir;
		} catch {
			/* try next base */
		}
	}
	return tmpdir();
}
function readCertCache(name: string): Buffer | null {
	try {
		const p = join(certCacheDir(), name);
		return existsSync(p) ? readFileSync(p) : null;
	} catch {
		return null;
	}
}
function writeCertCache(name: string, data: Buffer): void {
	try {
		writeFileSync(join(certCacheDir(), name), data);
	} catch {
		/* ignore cache write failures */
	}
}

export interface AttestationResult {
	attestation_verified: boolean;
	processor?: string;
	nilcc_version?: string;
	measurement?: string;
	measurement_matches_known_build?: boolean | null;
	report_data?: string;
	checks?: Record<string, boolean>;
	error?: string;
}

// Processor detection — exact ranges from the reference verify.rs. Returns null
// (→ fail closed) for any family/model outside the known SEV-SNP parts.
// Exported for offline tests.
export function detectProcessor(family: number, model: number): string | null {
	if (family === 0x19) {
		if (model <= 0x0f) return 'Milan';
		if ((model >= 0x10 && model <= 0x1f) || (model >= 0xa0 && model <= 0xaf)) return 'Genoa';
		return null;
	}
	if (family === 0x1a) return 'Turin';
	return null;
}

// r/s are little-endian 72-byte fields in the raw report; convert to 48-byte
// big-endian (IEEE-P1363).
function leToBe48(le: Buffer): Buffer {
	const be = Buffer.from(le).reverse();
	return be.subarray(be.length - 48);
}

// AMD SEV-SNP VCEK X.509 extension OIDs (value bytes, after the 06/len header).
const SNP_OID = {
	bootloader: '2b060104019c78010301',
	tee: '2b060104019c78010302',
	snp: '2b060104019c78010303',
	ucode: '2b060104019c78010308',
	hwid: '2b060104019c780104',
};

// Read an extension's value bytes out of the VCEK DER by scanning for its OID.
function extValue(der: Buffer, oidHex: string): Buffer | null {
	const oid = Buffer.from(oidHex, 'hex');
	const idx = der.indexOf(oid);
	if (idx < 0) return null;
	let p = idx + oid.length;
	if (der[p] === 0x01) p += 3; // skip optional critical BOOLEAN (01 01 FF)
	if (der[p] !== 0x04) return null; // extnValue OCTET STRING
	let len = der[p + 1];
	let start = p + 2;
	if (len & 0x80) {
		const n = len & 0x7f;
		len = 0;
		for (let i = 0; i < n; i++) len = (len << 8) | der[start + i];
		start += n;
	}
	return der.subarray(start, start + len);
}

function intExt(der: Buffer, oidHex: string): number | null {
	const v = extValue(der, oidHex);
	if (!v || v[0] !== 0x02) return null; // DER INTEGER
	return v[v.length - 1];
}

export interface ReportedTcb {
	bootloader: number;
	tee: number;
	snp: number;
	microcode: number;
}

// Cross-check the VCEK's embedded TCB + hardware ID against the report — parity
// with the reference verify_attestation_tcb. True only if every value matches.
// tcb/chipIdHex come from the SIGNED raw report, not the server's parsed JSON.
// Exported for offline tests.
export function verifyTcbExtensions(vcekDer: Buffer, tcb: ReportedTcb, chipIdHex: string): boolean {
	if (intExt(vcekDer, SNP_OID.bootloader) !== tcb.bootloader) return false;
	if (intExt(vcekDer, SNP_OID.tee) !== tcb.tee) return false;
	if (intExt(vcekDer, SNP_OID.snp) !== tcb.snp) return false;
	if (intExt(vcekDer, SNP_OID.ucode) !== tcb.microcode) return false;
	const hwid = extValue(vcekDer, SNP_OID.hwid);
	if (!hwid || hwid.toString('hex') !== chipIdHex) return false;
	return true;
}

// Parse an AMD KDS cert_chain PEM into { ark, ask }. The self-signed cert is the
// ARK. Returns null if the PEM doesn't yield exactly that pair (corrupt cache,
// KDS error page, etc.) so the caller can refetch instead of failing forever.
function parseCertChain(pem: string): { ark: X509Certificate; ask: X509Certificate } | null {
	try {
		const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
		let ark: X509Certificate | undefined;
		let ask: X509Certificate | undefined;
		for (const block of blocks) {
			const c = new X509Certificate(block);
			if (c.verify(c.publicKey)) ark = c;
			else ask = c;
		}
		return ark && ask ? { ark, ask } : null;
	} catch {
		return null;
	}
}

// Fetch the leaf TLS certificate (DER) the host presents — the cert nilCC binds
// into report_data. Resolves null on any connection/timeout error (fail-closed).
async function getServerCertDer(host: string): Promise<Buffer | null> {
	return new Promise((resolve) => {
		let settled = false;
		let socket: ReturnType<typeof tlsConnect> | undefined;
		const finish = (v: Buffer | null) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			try {
				socket?.destroy();
			} catch {
				/* ignore */
			}
			resolve(v);
		};
		// Guaranteed resolution — a stuck connection can never hang the node.
		const timer = setTimeout(() => finish(null), 7000);
		try {
			socket = tlsConnect({ host, port: 443, servername: host, rejectUnauthorized: true }, () => {
				try {
					const peer = socket!.getPeerCertificate() as { raw?: Buffer };
					finish(peer && peer.raw ? peer.raw : null);
				} catch {
					finish(null);
				}
			});
			socket.on('error', () => finish(null));
		} catch {
			finish(null);
		}
	});
}

// nilCC binds report_data = 0x00 || SHA-256(cert SubjectPublicKeyInfo) || zeros.
// Returns true iff the live host's TLS cert reproduces the report's report_data,
// including the 0x00 prefix byte and the all-zero tail (full reference parity).
// Exported for offline tests.
export function checkReportDataBinding(reportDataHex: string, certDer: Buffer): boolean {
	try {
		const spki = new X509Certificate(certDer).publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
		const fingerprint = createHash('sha256').update(spki).digest('hex');
		return (
			reportDataHex.length === 128 &&
			reportDataHex.slice(0, 2) === '00' &&
			reportDataHex.slice(2, 66) === fingerprint &&
			/^0+$/.test(reportDataHex.slice(66))
		);
	} catch {
		return false;
	}
}

/**
 * Verify the nilCC / AMD SEV-SNP attestation of the enclave serving nilAI.
 *
 * Ports Nillion's attestation-verification crate using only Node's built-in
 * crypto: fetches the hardware attestation report, fetches the chip's VCEK and
 * the AMD cert chain from AMD's KDS, verifies ARK→ASK→VCEK, verifies the report
 * signature (SHA-384 / ECDSA-P384), checks debug is disabled, and compares the
 * launch measurement against a known-good build.
 */
export async function verifyEnclaveAttestation(
	ctx: IExecuteFunctions,
	baseUrl: string,
): Promise<AttestationResult> {
	try {
		// 1. Fetch the hardware attestation report (public, unauthenticated).
		const reportResp = (await ctx.helpers.httpRequest({
			method: 'GET',
			url: `${baseUrl}/nilcc/api/v2/report`,
			json: true, timeout: 15000,
		})) as {
			report: Record<string, any>;
			raw_report: string;
			environment?: { nilcc_version?: string };
		};
		const report = reportResp.report;
		const raw = Buffer.from(reportResp.raw_report, 'hex');
		const nilccVersion = reportResp.environment?.nilcc_version;

		// A full SEV-SNP report is 0x4A0 bytes (signed region 0x2A0 + 0x200 signature).
		if (raw.length < 0x4a0) {
			throw new Error(`attestation report too short (${raw.length} bytes, expected 1184)`);
		}

		// 2. Derive every security-relevant value from the SIGNED raw report bytes.
		// The report signature proves the raw bytes — not the server's parsed JSON —
		// so trusting parsed fields (notably `policy`) would let a malicious server
		// lie about them. Layout per AMD SEV-SNP ABI (report v2/v3).
		// NOTE: TCB byte layout below is Milan/Genoa; Turin moves the fields (FMC) —
		// confirm against verify.rs before relying on it for a Turin deployment
		// (a mismatch fails closed via the VCEK fetch/cross-check).
		const policy = raw.readBigUInt64LE(0x08);
		const debugAllowed = ((policy >> 19n) & 1n) === 1n;
		const tcb: ReportedTcb = {
			bootloader: raw[0x180],
			tee: raw[0x181],
			snp: raw[0x186],
			microcode: raw[0x187],
		};
		const chipIdHex = raw.subarray(0x1a0, 0x1e0).toString('hex');
		// CPU family/model live in the raw report from v3; fall back to the parsed
		// fields for older versions (a lie there fails closed via the cert chain).
		const reportVersion = raw.readUInt32LE(0x00);
		const family = reportVersion >= 3 ? raw[0x188] : (report.cpuid_fam_id as number);
		const model = reportVersion >= 3 ? raw[0x189] : (report.cpuid_mod_id as number);

		const processor = detectProcessor(family, model);
		if (!processor) {
			throw new Error(
				`unsupported processor (family 0x${family.toString(16)}, model 0x${model.toString(16)})`,
			);
		}
		const pad2 = (n: number) => String(n).padStart(2, '0');

		// 3. Fetch AMD cert chain (ASK+ARK) and the chip's VCEK from KDS (cached).
		// Responses are parsed BEFORE being cached, and an unparseable cached file
		// triggers a refetch + overwrite — a KDS error page can't poison the cache.
		if (!certChainCache[processor]) {
			const chainCacheName = `certchain_${processor}.pem`;
			const cachedChain = readCertCache(chainCacheName);
			let chain = cachedChain ? parseCertChain(cachedChain.toString('utf8')) : null;
			if (!chain) {
				const chainPem = (await ctx.helpers.httpRequest({
					method: 'GET',
					url: `https://${KDS_DOMAIN}/vcek/v1/${processor}/cert_chain`,
					encoding: 'text',
					timeout: 15000,
				})) as string;
				chain = parseCertChain(chainPem);
				if (!chain) throw new Error('AMD KDS returned an unparseable certificate chain');
				writeCertCache(chainCacheName, Buffer.from(chainPem, 'utf8'));
			}
			certChainCache[processor] = chain;
		}
		const { ark, ask } = certChainCache[processor];

		const vcekUrl =
			`https://${KDS_DOMAIN}/vcek/v1/${processor}/${chipIdHex}` +
			`?blSPL=${pad2(tcb.bootloader)}&teeSPL=${pad2(tcb.tee)}&snpSPL=${pad2(tcb.snp)}&ucodeSPL=${pad2(tcb.microcode)}`;
		if (!vcekCache[vcekUrl]) {
			const vcekCacheName = `vcek_${chipIdHex}_${tcb.bootloader}_${tcb.tee}_${tcb.snp}_${tcb.microcode}.der`;
			const cachedDer = readCertCache(vcekCacheName);
			let vcekCert: X509Certificate | null = null;
			if (cachedDer) {
				try {
					vcekCert = new X509Certificate(cachedDer);
				} catch {
					vcekCert = null; // corrupt cache → refetch below
				}
			}
			if (!vcekCert) {
				const fetched = (await ctx.helpers.httpRequest({
					method: 'GET',
					url: vcekUrl,
					encoding: 'arraybuffer',
					timeout: 15000,
				})) as ArrayBuffer;
				const der = Buffer.from(fetched);
				vcekCert = new X509Certificate(der); // throws on a bad body — nothing cached
				writeCertCache(vcekCacheName, der);
			}
			vcekCache[vcekUrl] = vcekCert;
		}
		const vcek = vcekCache[vcekUrl];

		// 4. Verify the certificate chain: ARK self-signed → ARK signs ASK → ASK signs VCEK.
		const arkSelfSigned = ark.verify(ark.publicKey);
		const askByArk = ask.verify(ark.publicKey);
		const vcekByAsk = vcek.verify(ask.publicKey);

		// 5. Verify the report signature: SHA-384 over the first 0x2A0 bytes, ECDSA-P384.
		// r/s are read from the raw report (offsets 0x2A0/0x2E8, 72 bytes each, LE).
		const sig = Buffer.concat([
			leToBe48(raw.subarray(0x2a0, 0x2e8)),
			leToBe48(raw.subarray(0x2e8, 0x330)),
		]);
		const signedBytes = raw.subarray(0x0, 0x2a0);
		let sigValid = false;
		try {
			sigValid = cryptoVerify(
				'sha384',
				signedBytes,
				{ key: vcek.publicKey, dsaEncoding: 'ieee-p1363' },
				sig,
			);
		} catch {
			sigValid = false;
		}

		// 6. Surface measurement + TLS-cert binding (debug policy derived above, from raw).
		const measurement = raw.subarray(0x90, 0x90 + 48).toString('hex');
		const known = nilccVersion ? KNOWN_MEASUREMENTS[nilccVersion] : undefined;
		const measurementMatches = known ? measurement === known : null;
		// report_data binds the TLS certificate fingerprint into the signed report.
		const reportData = raw.subarray(0x50, 0x50 + 64).toString('hex');

		const tcbOk = verifyTcbExtensions(vcek.raw, tcb, chipIdHex);

		// TLS-session binding: the report's report_data embeds SHA-256 of the serving
		// cert's public key. Connect to the host, fetch its cert, and confirm it matches.
		const host = (() => {
			try {
				return new URL(baseUrl).hostname;
			} catch {
				return '';
			}
		})();
		const serverCertDer = host ? await getServerCertDer(host) : null;
		const tlsBound = serverCertDer ? checkReportDataBinding(reportData, serverCertDer) : false;

		const checks = {
			ark_self_signed: arkSelfSigned,
			ask_signed_by_ark: askByArk,
			vcek_signed_by_ask: vcekByAsk,
			report_signature_valid: sigValid,
			vcek_tcb_matches_report: tcbOk,
			tls_session_bound: tlsBound,
			debug_disabled: !debugAllowed,
		};
		// Hard-fail attestation on a known-measurement MISMATCH. If there is no
		// reference measurement for this nilcc_version, we don't fail on it
		// (it's surfaced as measurement_matches_known_build: null instead).
		const attestation_verified = Object.values(checks).every(Boolean) && measurementMatches !== false;

		return {
			attestation_verified,
			processor,
			nilcc_version: nilccVersion,
			measurement,
			measurement_matches_known_build: measurementMatches,
			report_data: reportData,
			checks,
		};
	} catch (e) {
		return { attestation_verified: false, error: (e as Error).message };
	}
}
