/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { Agent } from 'http';

declare module 'vscode-proxy-agent' {

	export interface ProxyAgentOptions {
		resolveProxy(url: string, callback: (proxy: string) => void): void;
	}
	
	export class ProxyAgent extends Agent {
		constructor(options: ProxyAgentOptions)
	}
}
