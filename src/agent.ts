import net from 'net';
import tls from 'tls';
import once from '@tootallnate/once';
import crypto from 'crypto';
import getUri from 'get-uri';
import createDebug from 'debug';
import getRawBody from 'raw-body';
import { Readable } from 'stream';
import { format, parse } from 'url';
import { HttpProxyAgent, HttpProxyAgentOptions } from 'http-proxy-agent';
import { HttpsProxyAgent, HttpsProxyAgentOptions } from 'https-proxy-agent';
import { SocksProxyAgent, SocksProxyAgentOptions } from 'socks-proxy-agent';
import createPacResolver, { FindProxyForURL, PacResolverOptions } from 'pac-resolver';
import {
	Agent,
	AgentCallbackReturn,
	AgentOptions,
	ClientRequest,
	RequestOptions
} from 'agent-base';

const debug = createDebug('pac-proxy-agent');

/**
 * The `PacProxyAgent` class.
 *
 * A few different "protocol" modes are supported (supported protocols are
 * backed by the `get-uri` module):
 *
 *   - "pac+data", "data" - refers to an embedded "data:" URI
 *   - "pac+file", "file" - refers to a local file
 *   - "pac+ftp", "ftp" - refers to a file located on an FTP server
 *   - "pac+http", "http" - refers to an HTTP endpoint
 *   - "pac+https", "https" - refers to an HTTPS endpoint
 *
 * @api public
 */
class _PacProxyAgent extends Agent {
	uri: string;
	opts: createPacProxyAgent.PacProxyAgentOptions;
	cache?: Readable;
	resolver?: FindProxyForURL;
	resolverHash: string;
	resolverPromise?: Promise<FindProxyForURL>;

	constructor(uri: string, opts: createPacProxyAgent.PacProxyAgentOptions = {}) {
		super(opts);
		debug('Creating PacProxyAgent with URI %o and options %o', uri, opts);

		// Strip the "pac+" prefix
		this.uri = uri.replace(/^pac\+/i, '');
		this.opts = { ...opts };
		this.cache = undefined;
		this.resolver = undefined;
		this.resolverHash = '';
		this.resolverPromise = undefined;

		// For `PacResolver`
		if (!this.opts.filename) {
			this.opts.filename = uri;
		}
	}

	private clearResolverPromise = (): void => {
		this.resolverPromise = undefined;
	};

	/**
	 * Loads the PAC proxy file from the source if necessary, and returns
	 * a generated `FindProxyForURL()` resolver function to use.
	 *
	 * @api private
	 */
	private getResolver(): Promise<FindProxyForURL> {
		if (!this.resolverPromise) {
			this.resolverPromise = this.loadResolver();
			this.resolverPromise.then(
				this.clearResolverPromise,
				this.clearResolverPromise
			);
		}
		return this.resolverPromise;
	}

	private async loadResolver(): Promise<FindProxyForURL> {
		try {
			// (Re)load the contents of the PAC file URI
			const code = await this.loadPacFile();

			// Create a sha1 hash of the JS code
			const hash = crypto
				.createHash('sha1')
				.update(code)
				.digest('hex');

			if (this.resolver && this.resolverHash === hash) {
				debug(
					'Same sha1 hash for code - contents have not changed, reusing previous proxy resolver'
				);
				return this.resolver;
			}

			// Cache the resolver
			debug('Creating new proxy resolver instance');
			this.resolver = createPacResolver(code, this.opts);

			// Store that sha1 hash for future comparison purposes
			this.resolverHash = hash;

			return this.resolver;
		} catch (err) {
			if (this.resolver && err.code === 'ENOTMODIFIED') {
				debug(
					'Got ENOTMODIFIED response, reusing previous proxy resolver'
				);
				return this.resolver;
			}
			throw err;
		}
	}

	/**
	 * Loads the contents of the PAC proxy file.
	 *
	 * @api private
	 */
	private async loadPacFile(): Promise<string> {
		debug('Loading PAC file: %o', this.uri);

		const rs = await getUri(this.uri, { cache: this.cache });
		debug('Got `Readable` instance for URI');
		this.cache = rs;

		const buf = await getRawBody(rs);
		debug('Read %o byte PAC file from URI', buf.length);

		return buf.toString('utf8');
	}

	/**
	 * Called when the node-core HTTP client library is creating a new HTTP request.
	 *
	 * @api protected
	 */
	async callback(
		req: ClientRequest,
		opts: RequestOptions
	): Promise<AgentCallbackReturn> {
		const { secureEndpoint } = opts;

		// First, get a generated `FindProxyForURL()` function,
		// either cached or retrieved from the source
		const resolver = await this.getResolver();

		// Calculate the `url` parameter
		const defaultPort = secureEndpoint ? 443 : 80;
		let path = req.path;
		let search: string | null = null;
		const firstQuestion = path.indexOf('?');
		if (firstQuestion !== -1) {
			search = path.substring(firstQuestion);
			path = path.substring(0, firstQuestion);
		}

		const urlOpts = {
			...opts,
			protocol: secureEndpoint ? 'https:' : 'http:',
			pathname: path,
			search,

			// need to use `hostname` instead of `host` otherwise `port` is ignored
			hostname: opts.host,
			host: null,
			href: null,

			// set `port` to null when it is the protocol default port (80 / 443)
			port: defaultPort === opts.port ? null : opts.port
		};
		const url = format(urlOpts);

		debug('url: %o', url);
		let result = await resolver(url);

		// Default to "DIRECT" if a falsey value was returned (or nothing)
		if (!result) {
			result = 'DIRECT';
		}

		const proxies = String(result)
			.trim()
			.split(/\s*;\s*/g)
			.filter(Boolean);

		if (this.opts.fallbackToDirect && !proxies.includes('DIRECT')) {
			proxies.push('DIRECT');
		}

		for (const proxy of proxies) {
			let agent: Agent | null = null;
			let socket: net.Socket | null = null;
			const [type, target] = proxy.split(/\s+/);
			debug('Attempting to use proxy: %o', proxy);

			if (type === 'DIRECT') {
				// Direct connection to the destination endpoint
				socket = secureEndpoint ? tls.connect(opts) : net.connect(opts);
			} else if (type === 'SOCKS' || type === 'SOCKS5') {
				// Use a SOCKSv5h proxy
				agent = new SocksProxyAgent(`socks://${target}`);
			} else if (type === 'SOCKS4') {
				// Use a SOCKSv4a proxy
				agent = new SocksProxyAgent(`socks4a://${target}`);
			} else if (
				type === 'PROXY' ||
				type === 'HTTP' ||
				type === 'HTTPS'
			) {
				// Use an HTTP or HTTPS proxy
				// http://dev.chromium.org/developers/design-documents/secure-web-proxy
				const proxyURL = `${
					type === 'HTTPS' ? 'https' : 'http'
				}://${target}`;
				const proxyOpts = { ...this.opts, ...parse(proxyURL) };
				if (secureEndpoint) {
					agent = new HttpsProxyAgent(proxyOpts);
				} else {
					agent = new HttpProxyAgent(proxyOpts);
				}
			}

			try {
				if (socket) {
					// "DIRECT" connection, wait for connection confirmation
					await once(socket, 'connect');
					req.emit('proxy', { proxy, socket });
					return socket;
				}
				if (agent) {
					const s = await agent.callback(req, opts);
					req.emit('proxy', { proxy, socket: s });
					return s;
				}
				throw new Error(`Could not determine proxy type for: ${proxy}`);
			} catch (err) {
				debug('Got error for proxy %o: %o', proxy, err);
				req.emit('proxy', { proxy, error: err });
			}
		}

		throw new Error(
			`Failed to establish a socket connection to proxies: ${JSON.stringify(
				proxies
			)}`
		);
	}
}

function createPacProxyAgent(
	uri: string,
	opts?: createPacProxyAgent.PacProxyAgentOptions
): _PacProxyAgent;
function createPacProxyAgent(
	opts: createPacProxyAgent.PacProxyAgentOptions
): _PacProxyAgent;
function createPacProxyAgent(
	uri?: string | createPacProxyAgent.PacProxyAgentOptions,
	opts?: createPacProxyAgent.PacProxyAgentOptions
): _PacProxyAgent {
	// was an options object passed in first?
	if (typeof uri === 'object') {
		opts = uri;

		// result of a url.parse() call?
		if (opts.href) {
			if (opts.path && !opts.pathname) {
				opts.pathname = opts.path;
			}
			opts.slashes = true;
			uri = format(opts);
		} else {
			uri = opts.uri;
		}
	}
	if (!opts) {
		opts = {};
	}

	if (typeof uri !== 'string') {
		throw new TypeError('a PAC file URI must be specified!');
	}

	return new _PacProxyAgent(uri, opts);
}

namespace createPacProxyAgent {
	export interface PacProxyAgentOptions
		extends AgentOptions,
			PacResolverOptions,
			HttpProxyAgentOptions,
			HttpsProxyAgentOptions,
			SocksProxyAgentOptions {
		uri?: string;
		fallbackToDirect?: boolean;
	}

	export type PacProxyAgent = _PacProxyAgent;
	export const PacProxyAgent = _PacProxyAgent;

	/**
	 * Supported "protocols". Delegates out to the `get-uri` module.
	 */
	export const protocols = Object.keys(getUri.protocols);

	createPacProxyAgent.prototype = _PacProxyAgent.prototype;
}

export = createPacProxyAgent;