import {
	IExecuteFunctions,
	ILoadOptionsFunctions,
	INodeExecutionData,
	INodePropertyOptions,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

import { createPublicKey, verify as cryptoVerify } from 'crypto';

import { verifyEnclaveAttestation } from './attestation';

// DER SubjectPublicKeyInfo prefix for an EC public key on the secp256k1 curve,
// with a compressed point (0x03 22 = BIT STRING of 33 bytes). Concatenated with
// the 33-byte compressed point this forms a key OpenSSL/Node can import directly.
const SPKI_SECP256K1_COMPRESSED_PREFIX = Buffer.from(
	'3036301006072a8648ce3d020106052b8104000a032200',
	'hex',
);

function publicKeyFromCompressedBase64(b64: string) {
	const point = Buffer.from(b64.trim().replace(/^"|"$/g, ''), 'base64');
	const spki = Buffer.concat([SPKI_SECP256K1_COMPRESSED_PREFIX, point]);
	return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

/**
 * Verify a nilAI signed response.
 *
 * nilAI signs the *Pydantic* JSON serialisation of the response object with the
 * `signature` field blanked, using secp256k1 ECDSA over SHA-256. The HTTP body we
 * receive differs from that serialisation only in float formatting (e.g. Pydantic
 * emits `1.0` where the body shows `1`), so we rebuild the signed pre-image from the
 * raw body: blank the signature, then re-add `.0` to the float-typed fields.
 */
export function verifyNilaiSignature(rawBody: string, publicKeyB64: string): boolean {
	try {
		const obj = JSON.parse(rawBody);
		const signatureB64: string | undefined = obj.signature;
		if (!signatureB64) return false;

		// Blank the signature by replacing its exact (high-entropy, unambiguous)
		// value — not the first "signature":"…" pattern, which could match inside
		// the model's own output text and corrupt the pre-image.
		let preimage = rawBody.replace(`"signature":"${signatureB64}"`, '"signature":""');
		for (const field of ['created_at', 'temperature', 'top_p']) {
			preimage = preimage.replace(
				new RegExp(`("${field}":)(-?\\d+)([,}\\]])`),
				'$1$2.0$3',
			);
		}

		const publicKey = publicKeyFromCompressedBase64(publicKeyB64);
		return cryptoVerify(
			'sha256',
			Buffer.from(preimage, 'utf8'),
			{ key: publicKey, dsaEncoding: 'der' },
			Buffer.from(signatureB64, 'base64'),
		);
	} catch {
		return false;
	}
}

export class NilAi implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'nilAI',
		name: 'nilAi',
		icon: { light: 'file:nilai.svg', dark: 'file:nilai-dark.svg' },
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["model"]}}',
		description:
			'Private, verifiable AI inference inside a Trusted Execution Environment (TEE), powered by Nillion nilAI.',
		usableAsTool: true,
		defaults: {
			name: 'nilAI',
		},
		inputs: ['main'] as NodeConnectionType[],
		outputs: ['main'] as NodeConnectionType[],
		credentials: [
			{
				name: 'nilAiApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Model Name or ID',
				name: 'model',
				type: 'options',
				typeOptions: {
					loadOptionsMethod: 'getModels',
				},
				default: '',
				description: 'The model to run inside the nilAI TEE. Loaded live from your nilAI endpoint. Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code/expressions/">expression</a>.',
			},
			{
				displayName: 'Instructions',
				name: 'instructions',
				type: 'string',
				typeOptions: {
					rows: 2,
				},
				default: '',
				description: 'What you want the model to do, e.g. \'Summarise this in 3 sentences and 3-5 key bullet points\'',
				hint: 'Plain text — the task only. Keep your data out of here (put that in Input). Leave empty to send just the Input as-is.',
			},
			{
				displayName: 'Input',
				name: 'prompt',
				type: 'string',
				typeOptions: {
					rows: 4,
				},
				default: '',
				required: true,
				description: 'The content to act on. The model receives Instructions followed by this.',
				hint: 'Usually a reference to data from a previous node — e.g. the document text. Instructions + Input are combined into the prompt for you.',
			},
			{
				displayName: 'Simplify Output',
				name: 'simplify',
				type: 'boolean',
				default: true,
				description: 'Whether to return a clean result instead of nilAI\'s full raw response object',
				hint: 'On: tidy output — just the answer, the verification results and token usage. Off: the complete raw nilAI response (every field), handy for debugging.',
			},
			{
				displayName: 'Verify TEE Signature',
				name: 'verify',
				type: 'boolean',
				default: true,
				description:
					"Whether to cryptographically verify this response's signature against the enclave's key. Adds a tee_verified field.",
				hint: 'Proves THIS response was signed inside the nilAI enclave and was not altered in transit. Adds tee_verified (true/false).',
			},
			{
				displayName: 'Verify Enclave Attestation',
				name: 'verifyAttestation',
				type: 'boolean',
				default: true,
				description:
					"Whether to verify the serving enclave's AMD SEV-SNP hardware attestation against AMD's certificate chain. Adds an attestation object.",
				hint: "Proves the SERVER is a genuine AMD SEV-SNP TEE running the expected nilAI build (chained to AMD's root certificates). Independent of the signature check — use either or both.",
			},
		],
	};

	methods = {
		loadOptions: {
			async getModels(this: ILoadOptionsFunctions): Promise<INodePropertyOptions[]> {
				const credentials = await this.getCredentials('nilAiApi');
				const baseUrl = ((credentials.baseUrl as string) || 'https://api.nilai.nillion.network').replace(/\/+$/, '');
				const response = await this.helpers.httpRequestWithAuthentication.call(this, 'nilAiApi', {
					method: 'GET',
					url: `${baseUrl}/v1/models`,
					json: true,
				});
				const models = (response?.data ?? response) as Array<{ id: string }>;
				if (!Array.isArray(models)) return [];
				return models
					.map((model) => ({ name: model.id, value: model.id }))
					.sort((a, b) => a.name.localeCompare(b.name));
			},
		},
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		const credentials = await this.getCredentials('nilAiApi');
		const baseUrl = ((credentials.baseUrl as string) || 'https://api.nilai.nillion.network').replace(/\/+$/, '');

		// The enclave attestation is a property of the serving environment, not of an
		// individual response — verify it once and attach it to every output item.
		const verifyAttestation = this.getNodeParameter('verifyAttestation', 0, true) as boolean;
		const attestation: any = verifyAttestation ? await verifyEnclaveAttestation(this, baseUrl) : undefined;

		// The enclave public key is likewise per-environment — fetch it once, lazily.
		let publicKeyB64: string | undefined;

		for (let i = 0; i < items.length; i++) {
			try {
				const model = this.getNodeParameter('model', i) as string;
				const instructions = this.getNodeParameter('instructions', i, '') as string;
				const prompt = this.getNodeParameter('prompt', i) as string;
				const doVerify = this.getNodeParameter('verify', i) as boolean;
				const simplify = this.getNodeParameter('simplify', i) as boolean;

				// Request the RAW response bytes (encoding: 'arraybuffer') so the exact signed
				// bytes are preserved. The signature is over these exact bytes; any JSON
				// re-parse/re-serialise would change float formatting and break verification.
				const rawResponse = await this.helpers.httpRequestWithAuthentication.call(this, 'nilAiApi', {
					method: 'POST',
					url: `${baseUrl}/v1/responses`,
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ model, input: [instructions, prompt].map((s) => (s || '').trim()).filter(Boolean).join('\n\n') }),
					json: false,
					encoding: 'arraybuffer',
				});
				const rawBody =
					typeof rawResponse === 'string'
						? rawResponse
						: Buffer.from(rawResponse as ArrayBuffer).toString('utf8');

				const parsed = JSON.parse(rawBody);

				let teeVerified: boolean | null = null;
				if (doVerify) {
					if (publicKeyB64 === undefined) {
						publicKeyB64 = (await this.helpers.httpRequestWithAuthentication.call(this, 'nilAiApi', {
							method: 'GET',
							url: `${baseUrl}/v1/public_key`,
							json: true,
							timeout: 15000,
						})) as string;
					}
					teeVerified = verifyNilaiSignature(rawBody, publicKeyB64);
				}

				// Find the message-type output item (some models, e.g. gpt-oss, emit a
				// reasoning item first, so output[0] isn't always the answer).
				const outputItems: any[] = Array.isArray(parsed?.output) ? parsed.output : [];
				const message = outputItems.find((o: any) => o?.type === 'message') ?? outputItems[0];
				const contents: any[] = Array.isArray(message?.content) ? message.content : [];
				const part = contents.find((c: any) => c?.type === 'output_text') ?? contents[0];
				const text: string | null = typeof part?.text === 'string' ? part.text : null;

				if (simplify) {
					returnData.push({
						json: {
							text,
							tee_verified: teeVerified,
							attestation,
							model: parsed?.model,
							signature: parsed?.signature ?? null,
							usage: parsed?.usage ?? null,
						},
						pairedItem: { item: i },
					});
				} else {
					returnData.push({
						json: { ...parsed, tee_verified: teeVerified, attestation },
						pairedItem: { item: i },
					});
				}
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: { error: (error as Error).message },
						pairedItem: { item: i },
					});
					continue;
				}
				throw new NodeOperationError(this.getNode(), error as Error, { itemIndex: i });
			}
		}

		return [returnData];
	}
}
