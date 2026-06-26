/**
 * Offline test harness for n8n-nodes-nilai (attestation + signature verification).
 * Uses captured artifacts from nilai_attest/: report.json, vcek.der, cert_chain.pem,
 * server_cert.der. No network access required — httpRequest and tls.connect are mocked.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const tls = require('tls');

const BUILD = process.env.BUILD_DIR || path.join(__dirname, "..");
const ART = process.env.ART_DIR || path.join(__dirname, "..", "..", "nilai_attest");

const reportJson = JSON.parse(fs.readFileSync(path.join(ART, 'report.json'), 'utf8'));
const vcekDer = fs.readFileSync(path.join(ART, 'vcek.der'));
const chainPem = fs.readFileSync(path.join(ART, 'cert_chain.pem'), 'utf8');
const serverCertDer = fs.readFileSync(path.join(ART, 'server_cert.der'));

let passed = 0;
let failed = 0;
function check(name, cond, extra) {
  if (cond) {
    passed++;
    console.log(`  ok  ${name}`);
  } else {
    failed++;
    console.log(`FAIL  ${name}${extra ? ' — ' + extra : ''}`);
  }
}

// ---- tls.connect mock: serve a chosen cert without touching the network ----
let tlsCertToServe = serverCertDer;
const realTlsConnect = tls.connect;
tls.connect = (opts, cb) => {
  const socket = {
    on() {},
    destroy() {},
    getPeerCertificate() {
      return { raw: tlsCertToServe };
    },
  };
  setImmediate(cb);
  return socket;
};

// ---- module loader: fresh module state + fresh cert-cache dir per scenario ----
function freshAttestation() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'nilai-test-home-'));
  process.env.HOME = home;
  const mod = path.join(BUILD, 'dist/nodes/NilAi/attestation.js');
  delete require.cache[require.resolve(mod)];
  return { att: require(mod), cacheDir: path.join(home, '.n8n', '.nilai-cert-cache') };
}

function makeCtx(overrides = {}) {
  return {
    helpers: {
      httpRequest: async (opts) => {
        const url = opts.url;
        if (url.includes('/nilcc/api/v2/report')) {
          if (overrides.report) return overrides.report;
          return JSON.parse(JSON.stringify(reportJson));
        }
        if (url.includes('cert_chain')) {
          if (overrides.chain !== undefined) return overrides.chain;
          return chainPem;
        }
        if (url.includes('/vcek/v1/')) {
          if (overrides.vcek !== undefined) return overrides.vcek;
          return vcekDer.buffer.slice(vcekDer.byteOffset, vcekDer.byteOffset + vcekDer.byteLength);
        }
        throw new Error('unexpected URL in test: ' + url);
      },
    },
  };
}

const BASE = 'https://api.nilai.nillion.network';

(async () => {
  // ---------- 1. unit: detectProcessor ----------
  {
    const { att } = freshAttestation();
    check('detectProcessor Milan (0x19/0x05)', att.detectProcessor(0x19, 0x05) === 'Milan');
    check('detectProcessor Genoa (0x19/0x11)', att.detectProcessor(0x19, 0x11) === 'Genoa');
    check('detectProcessor Genoa (0x19/0xA5)', att.detectProcessor(0x19, 0xa5) === 'Genoa');
    check('detectProcessor rejects 0x19/0x50', att.detectProcessor(0x19, 0x50) === null);
    check('detectProcessor Turin (0x1A)', att.detectProcessor(0x1a, 0x02) === 'Turin');
    check('detectProcessor rejects unknown family', att.detectProcessor(0x17, 0x01) === null);
  }

  // ---------- 2. unit: checkReportDataBinding ----------
  {
    const { att } = freshAttestation();
    const raw = Buffer.from(reportJson.raw_report, 'hex');
    const reportData = raw.subarray(0x50, 0x90).toString('hex');
    check('TLS binding: real cert matches report_data', att.checkReportDataBinding(reportData, serverCertDer));
    check('TLS binding: wrong cert rejected', !att.checkReportDataBinding(reportData, vcekDer));
    const badPrefix = 'ff' + reportData.slice(2);
    check('TLS binding: non-zero prefix byte rejected', !att.checkReportDataBinding(badPrefix, serverCertDer));
    const badTail = reportData.slice(0, 126) + 'ff';
    check('TLS binding: non-zero tail rejected', !att.checkReportDataBinding(badTail, serverCertDer));
    check('TLS binding: short report_data rejected', !att.checkReportDataBinding(reportData.slice(0, 80), serverCertDer));
  }

  // ---------- 3. unit: verifyTcbExtensions ----------
  {
    const { att } = freshAttestation();
    const raw = Buffer.from(reportJson.raw_report, 'hex');
    const tcb = { bootloader: raw[0x180], tee: raw[0x181], snp: raw[0x186], microcode: raw[0x187] };
    const chipId = raw.subarray(0x1a0, 0x1e0).toString('hex');
    check('TCB ext: real VCEK matches raw report', att.verifyTcbExtensions(vcekDer, tcb, chipId));
    check('TCB ext: wrong snp rejected', !att.verifyTcbExtensions(vcekDer, { ...tcb, snp: tcb.snp + 1 }, chipId));
    check('TCB ext: wrong chip_id rejected', !att.verifyTcbExtensions(vcekDer, tcb, 'ab'.repeat(64)));
  }

  // ---------- 4. end-to-end positive ----------
  {
    const { att, cacheDir } = freshAttestation();
    const r = await att.verifyEnclaveAttestation(makeCtx(), BASE);
    check('e2e positive: attestation_verified', r.attestation_verified === true, JSON.stringify(r));
    check('e2e positive: processor Genoa', r.processor === 'Genoa');
    check('e2e positive: measurement matches pin', r.measurement_matches_known_build === true);
    check('e2e positive: all checks true', r.checks && Object.values(r.checks).every(Boolean));
    check('e2e positive: chain cached after parse', fs.existsSync(path.join(cacheDir, 'certchain_Genoa.pem')));
  }

  // ---------- 5. tamper: flip a byte in the signed region ----------
  {
    const { att } = freshAttestation();
    const report = JSON.parse(JSON.stringify(reportJson));
    const raw = Buffer.from(report.raw_report, 'hex');
    raw[0x95] ^= 0xff; // inside measurement, inside signed region
    report.raw_report = raw.toString('hex');
    const r = await att.verifyEnclaveAttestation(makeCtx({ report }), BASE);
    check('tamper: report_signature_valid false', r.checks && r.checks.report_signature_valid === false);
    check('tamper: attestation_verified false', r.attestation_verified === false);
  }

  // ---------- 6. parsed-JSON lies are ignored (raw report wins) ----------
  {
    const { att } = freshAttestation();
    const report = JSON.parse(JSON.stringify(reportJson));
    report.report.policy = 0x80000 + 0x30000; // lie: claim debug allowed in the parse
    report.report.reported_tcb.snp = 99; // lie: wrong TCB in the parse
    report.report.chip_id = 'ab'.repeat(64); // lie: wrong chip in the parse
    const r = await att.verifyEnclaveAttestation(makeCtx({ report }), BASE);
    check('parse-lie: debug check reads raw (still disabled)', r.checks && r.checks.debug_disabled === true);
    check('parse-lie: TCB cross-check reads raw (still ok)', r.checks && r.checks.vcek_tcb_matches_report === true);
    check('parse-lie: attestation still verified', r.attestation_verified === true, JSON.stringify(r));
  }

  // ---------- 7. unsupported processor fails closed ----------
  {
    const { att } = freshAttestation();
    const report = JSON.parse(JSON.stringify(reportJson));
    const raw = Buffer.from(report.raw_report, 'hex');
    raw[0x188] = 0x20; // unknown family in the raw (v3) report
    report.raw_report = raw.toString('hex');
    const r = await att.verifyEnclaveAttestation(makeCtx({ report }), BASE);
    check('unknown processor: fails closed', r.attestation_verified === false && /unsupported processor/i.test(r.error || ''), JSON.stringify(r));
  }

  // ---------- 8. truncated raw report fails closed ----------
  {
    const { att } = freshAttestation();
    const report = JSON.parse(JSON.stringify(reportJson));
    report.raw_report = report.raw_report.slice(0, 0x2a0 * 2); // cut off the signature
    const r = await att.verifyEnclaveAttestation(makeCtx({ report }), BASE);
    check('truncated report: fails closed', r.attestation_verified === false && /too short/.test(r.error || ''), JSON.stringify(r));
  }

  // ---------- 9. cache poisoning self-heals ----------
  {
    const { att, cacheDir } = freshAttestation();
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(path.join(cacheDir, 'certchain_Genoa.pem'), 'HTTP 429 Too Many Requests');
    const raw = Buffer.from(reportJson.raw_report, 'hex');
    const tcb = { bl: raw[0x180], tee: raw[0x181], snp: raw[0x186], uc: raw[0x187] };
    const chipId = raw.subarray(0x1a0, 0x1e0).toString('hex');
    const vcekName = `vcek_${chipId}_${tcb.bl}_${tcb.tee}_${tcb.snp}_${tcb.uc}.der`;
    fs.writeFileSync(path.join(cacheDir, vcekName), 'not a certificate');
    const r = await att.verifyEnclaveAttestation(makeCtx(), BASE);
    check('poisoned cache: self-heals to verified', r.attestation_verified === true, JSON.stringify(r));
    const healedChain = fs.readFileSync(path.join(cacheDir, 'certchain_Genoa.pem'), 'utf8');
    check('poisoned cache: chain file overwritten with good data', healedChain.includes('BEGIN CERTIFICATE'));
    check('poisoned cache: vcek file overwritten with good data', fs.readFileSync(path.join(cacheDir, vcekName)).equals(vcekDer));
  }

  // ---------- 10. KDS error page is NOT cached ----------
  {
    const { att, cacheDir } = freshAttestation();
    const r = await att.verifyEnclaveAttestation(makeCtx({ chain: '<html>503 Service Unavailable</html>' }), BASE);
    check('KDS error: fails closed', r.attestation_verified === false && /unparseable certificate chain/.test(r.error || ''), JSON.stringify(r));
    check('KDS error: nothing written to cache', !fs.existsSync(path.join(cacheDir, 'certchain_Genoa.pem')));
  }

  // ---------- 11. TLS substitution rejected end-to-end ----------
  {
    const { att } = freshAttestation();
    tlsCertToServe = vcekDer; // wrong cert served by the "host"
    const r = await att.verifyEnclaveAttestation(makeCtx(), BASE);
    tlsCertToServe = serverCertDer;
    check('TLS substitution: tls_session_bound false', r.checks && r.checks.tls_session_bound === false);
    check('TLS substitution: attestation_verified false', r.attestation_verified === false);
  }

  // ---------- 12. response-signature verification round-trip ----------
  {
    const nodeMod = path.join(BUILD, 'dist/nodes/NilAi/NilAi.node.js');
    delete require.cache[require.resolve(nodeMod)];
    const { verifyNilaiSignature } = require(nodeMod);

    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const jwk = publicKey.export({ format: 'jwk' });
    const x = Buffer.from(jwk.x, 'base64url');
    const y = Buffer.from(jwk.y, 'base64url');
    const compressed = Buffer.concat([Buffer.from([y[31] & 1 ? 0x03 : 0x02]), x]);
    const pubB64 = compressed.toString('base64');

    // Pydantic-style signed pre-image: floats with .0, signature blanked. Includes a
    // DECOY nested "signature" key appearing BEFORE the real one (the old first-match
    // regex blanked the decoy and broke verification; exact-value matching must not).
    const signedStr =
      '{"id":"resp_test","created_at":1780406159.0,"model":"google/gemma-4-26B-A4B-it",' +
      '"sources":[{"signature":"DECOYVALUE","doc":"nilRAG source"}],' +
      '"output":[{"type":"message","content":[{"type":"output_text","text":"hello world"}]}],' +
      '"temperature":1.0,"top_p":1.0,"signature":"","usage":{"total_tokens":10}}';
    const sigB64 = crypto.sign('sha256', Buffer.from(signedStr, 'utf8'), { key: privateKey, dsaEncoding: 'der' }).toString('base64');

    // Wire form: signature filled in, float-typed fields rendered as bare ints.
    const wire = signedStr
      .replace('"signature":""', `"signature":"${sigB64}"`)
      .replace('"created_at":1780406159.0', '"created_at":1780406159')
      .replace('"temperature":1.0', '"temperature":1')
      .replace('"top_p":1.0', '"top_p":1');

    check('signature round-trip: verifies', verifyNilaiSignature(wire, pubB64) === true);
    check('signature round-trip: tampered body rejected', verifyNilaiSignature(wire.replace('hello world', 'hello w0rld'), pubB64) === false);
    check('signature round-trip: wrong key rejected', verifyNilaiSignature(wire, Buffer.concat([Buffer.from([0x02]), crypto.randomBytes(32)]).toString('base64')) === false);

    // Demonstrate the old approach really did break on the decoy:
    const oldBlank = wire.replace(/"signature":"[^"]*"/, '"signature":""');
    check('old first-match regex hits the decoy (regression proof)', oldBlank.includes('DECOYVALUE') === false && oldBlank.includes(sigB64));
  }

  tls.connect = realTlsConnect;
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error('HARNESS ERROR:', e);
  process.exit(2);
});
