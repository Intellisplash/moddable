import type { DNSUDPDevice } from "embedded:network/dns/resolver/udp";
import type { TLSDevice } from "embedded:io/socket/tcp/tls";
import type WebSocketClient from "embedded:network/websocket/client";

declare global {
	interface WSNetwork {
		ws: {
			io: typeof WebSocketClient;
			dns: DNSUDPDevice;
		};
		wss: {
			io: typeof WebSocketClient;
			dns: DNSUDPDevice;
			socket: TLSDevice;
		};
	}

	interface Device {
		network: WSNetwork;
	}
}

