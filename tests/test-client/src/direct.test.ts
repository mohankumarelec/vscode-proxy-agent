import * as https from 'https';
import { ClientRequest, RequestOptions } from 'http';
import * as vpa from '../../..';
import { testRequest, ca } from './utils';
import * as assert from 'assert';

describe('Direct client', function () {
	it('should work without agent', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			ca,
		});
	});
	it('should support SNI when not proxied', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: new vpa.ProxyAgent({
				resolveProxy: (req: ClientRequest, opts: RequestOptions, url: string, cb: (res: string) => void) => cb('DIRECT'),
				defaultPort: 443
			}),
			ca,
		});
	});
	it('should omit default port in host header', function () {
		// https://github.com/Microsoft/vscode/issues/65118
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: new vpa.ProxyAgent({
				resolveProxy: (req: ClientRequest, opts: RequestOptions, url: string, cb: (res: string) => void) => cb('DIRECT'),
				defaultPort: 443
			}),
			ca,
		}, {
			assertResult: result => {
				assert.equal(result.headers.host, 'test-https-server');
			}
		});
	});
	it('should should fall back to original agent when not proxied', function () {
		// https://github.com/Microsoft/vscode/issues/68531
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: new vpa.ProxyAgent({
				resolveProxy: (req: ClientRequest, opts: RequestOptions, url: string, cb: (res: string) => void) => cb('DIRECT'),
				defaultPort: 443,
				originalAgent: {
					addRequest: (req: any, opts: any) => {
						req.setHeader('original-agent', 'true');
						(<any>https.globalAgent).addRequest(req, opts);
					}
				} as any
			}),
			ca,
		}, {
			assertResult: result => {
				assert.equal(result.headers['original-agent'], 'true');
			}
		});
	});
	it('should should handle `false` as the original agent', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: new vpa.ProxyAgent({
				resolveProxy: (req: ClientRequest, opts: RequestOptions, url: string, cb: (res: string) => void) => cb('DIRECT'),
				defaultPort: 443,
				originalAgent: false
			}),
			ca,
		});
	});
});
