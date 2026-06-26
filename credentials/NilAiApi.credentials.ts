import {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class NilAiApi implements ICredentialType {
	name = 'nilAiApi';

	displayName = 'nilAI API';

	icon = 'file:nilai.svg' as const;

	documentationUrl = 'https://developer.nillion.com/nilai';

	properties: INodeProperties[] = [
		{
			displayName:
				'Don\'t have a key yet? Create a free nilAI account with starter credit at <a href="https://developer.nillion.com/nilai" target="_blank">developer.nillion.com/nilai</a>.',
			name: 'signupNotice',
			type: 'notice',
			default: '',
		},
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description:
				'Paste your nilAI API key. Get one free (with starter credit) at developer.nillion.com/nilai.',
		},
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: 'https://api.nilai.nillion.network',
			description: 'nilAI API base URL. Defaults to Nillion mainnet.',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization: '=Bearer {{$credentials.apiKey}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.baseUrl}}',
			url: '/v1/models',
		},
	};
}
