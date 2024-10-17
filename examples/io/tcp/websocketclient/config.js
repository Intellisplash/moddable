import "system"		// system initializes globalThis.device. this ensures it runs before this module.

import TCP from "embedded:io/socket/tcp";
import TLSSocket from 'embedded:io/socket/tcp/tls';
import UDP from "embedded:io/socket/udp";
import Resolver from "embedded:network/dns/resolver/udp";

import WebSocketClient from "embedded:network/websocket/client";

const dns = {
	io: Resolver,
	servers: [
		"1.1.1.1",
		"8.8.8.8"
	],
	socket: {
		io: UDP,
	},
};
globalThis.device = Object.freeze({
	...globalThis.device,
	network: {
		...globalThis.device?.network,
		ws: {
			client: {	
				dns,
				socket: {
					io: TCP
				}
			},
			io: WebSocketClient,
			// todo: are these legacy?
			dns,
			socket: {
				io: TCP,
			}
		},
		wss: {
			client: {
				dns,
				socket: {
					io: TLSSocket
				}
			},
			io: WebSocketClient
		}
	},
}, true);

