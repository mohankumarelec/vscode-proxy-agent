import * as https from 'https';
import * as vpa from '../../..';
import { testRequest, ca } from './utils';

describe('Proxied client', function () {
	it('should use HTTP proxy for HTTPS connection', function () {
		return testRequest(https, {
			hostname: 'test-https-server',
			path: '/test-path',
			agent: new vpa.ProxyAgent({
				resolveProxy: (url: string, cb: (res: string) => void) => cb('PROXY test-http-proxy:3128')
			}),
			ca,
		});
	});
});
