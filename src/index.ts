/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Nathan Rajlich, Félicien François, Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as http from 'http';
import { parse, format } from 'url';
import HttpProxyAgent from 'http-proxy-agent';
import HttpsProxyAgent from 'https-proxy-agent';
import debug from 'debug';
const SocksProxyAgent = require('socks-proxy-agent');

const debugLog = debug('vscode-proxy-agent');

export interface ProxyAgentOptions {
  resolveProxy(req: http.ClientRequest, opts: http.RequestOptions, url: string, callback: (proxy: string | undefined) => void): void;
  defaultPort: number;
  originalAgent?: http.Agent | false;
}

export class ProxyAgent0 {
  public defaultPort: number | undefined;
  constructor(public session: ProxyAgentOptions) {
    if (!(this instanceof ProxyAgent0)) return new ProxyAgent0(session);
    this.defaultPort = session.defaultPort;
  }
  public addRequest = addRequest;
}

function addRequest(this: ProxyAgent0, req: http.ClientRequest, opts: http.RequestOptions) {
  var url: string;
  var self = this;

  // calculate the `url` parameter
  var defaultAgent = opts._defaultAgent || http.globalAgent;
  var path = req.path;
  var firstQuestion = path.indexOf('?');
  var search: string | undefined;
  if (-1 != firstQuestion) {
    search = path.substring(firstQuestion);
    path = path.substring(0, firstQuestion);
  }
  url = format(Object.assign({}, opts, {
    protocol: (defaultAgent as any).protocol,
    pathname: path,
    search: search,

    // need to use `hostname` instead of `host` otherwise `port` is ignored
    hostname: opts.host,
    host: null,

    // set `port` to null when it is the protocol default port (80 / 443)
    port: (defaultAgent as any).defaultPort == opts.port ? null : opts.port
  }));

  debugLog('url: %o', url);
  self.session.resolveProxy(req, opts, url, onproxy);

  // `resolveProxy()` callback function
  function onproxy(proxy: string | undefined) {

    // default to "DIRECT" if a falsey value was returned (or nothing)
    if (!proxy) proxy = 'DIRECT';

    var proxies = String(proxy).trim().split(/\s*;\s*/g).filter(Boolean);

    // XXX: right now, only the first proxy specified will be used
    var first = proxies[0];
    debugLog('using proxy: %o', first);

    var agent;
    var parts = first.split(/\s+/);
    var type = parts[0];

    if ('DIRECT' == type) {
      // direct connection to the destination endpoint
      agent = getDirectAgent(self.session.originalAgent, defaultAgent);
    } else if ('SOCKS' == type) {
      // use a SOCKS proxy
      agent = new SocksProxyAgent('socks://' + parts[1]);
    } else if ('PROXY' == type || 'HTTPS' == type) {
      // use an HTTP or HTTPS proxy
      // http://dev.chromium.org/developers/design-documents/secure-web-proxy
      var proxyURL = ('HTTPS' === type ? 'https' : 'http') + '://' + parts[1];
      const proxy = parse(proxyURL);
      if ((defaultAgent as any).protocol === 'https:') {
        agent = new HttpsProxyAgent(proxy as any);
      } else {
        agent = new HttpProxyAgent(proxy);
      }
    } else {
      // direct connection to the destination endpoint
      agent = getDirectAgent(self.session.originalAgent, defaultAgent);
    }
    agent.addRequest(req, opts);
  }
}

function getDirectAgent(originalAgent: http.Agent | false | undefined, defaultAgent: http.Agent) {
  if (originalAgent === false) {
    return new (defaultAgent as any).constructor();
  }
  return originalAgent || defaultAgent;
}

export const ProxyAgent: { new (session: ProxyAgentOptions): http.Agent; } = ProxyAgent0 as any;
