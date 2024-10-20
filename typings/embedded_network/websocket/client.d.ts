declare module "embedded:network/websocket/client" {
	import type { DNSUDPDevice } from "embedded:network/dns/resolver/udp";
	import type { Buffer } from "embedded:io/_common";
	import type TCP from "embedded:io/socket/tcp";
	import type { TCPDevice } from "embedded:io/socket/tcp";
	import type TLSSocket from "embedded:io/socket/tcp/tls";
	import type { TLSDevice } from "embedded:io/socket/tcp/tls";
	import "embedded:network/websocket/client-device";
	
	interface WebSocketClientReadableOptions {
		more: boolean;
		binary: boolean;
	}

	export interface WebSocketClientWriteOptions {
		binary?: boolean;
		more?: boolean;
		opcode?: WebSocketClientOpcode;
	}

	type WebSocketClientOpcode = 1 | 2 | 8 | 9 | 10;

	type WebSocketClientOptions = ((
		{
			attach?: TCP | TLSSocket;
		} | {
			host?: string;
			port?: number;
			socket: TCPDevice | TLSDevice;
		}) & {
			protocol?: string;
			headers?: Map<string, string>;
			dns?: DNSUDPDevice;
			onReadable?: (count: number, options?: WebSocketClientReadableOptions) => void;
			onWritable?: (count: number) => void;
			onControl?: (opcode: WebSocketClientOpcode, buffer: Uint8Array) => void; // should this be ArrayBuffer?
			onClose?: () => void;
			onError?: () => void;
		}
	);

	export type WebSocketClientDevice = WebSocketClientOptions & { io: typeof WebSocketClient };

	export default class WebSocketClient {
		constructor(options: WebSocketClientOptions);
		close(): void;
		read(count?: number): ArrayBuffer;
		write(message: Buffer, options?: WebSocketClientWriteOptions): number;

		static readonly text: 1;
		static readonly binary: 2;
		static readonly close: 8;
		static readonly ping: 9;
		static readonly pong: 10;
	}
}
