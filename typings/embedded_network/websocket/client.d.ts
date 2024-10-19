declare module "embedded:network/websocket/client" {
	import type { DNSUDPOptions } from "embedded:network/dns/resolver/udp";
	import type { Buffer } from "embedded:io/_common";
	import type TCP from "embedded:io/socket/tcp";
	import type { TCPOptions } from "embedded:io/socket/tcp";
	import type TLSSocket from "embedded:io/socket/tcp/tls";
	import type { TLSOptions } from "embedded:io/socket/tcp/tls";
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

	interface WebSocketClientOptions {
		attach?: TCP | TLSSocket;
		socket?: TCPOptions | TLSOptions;
		host?: string;
		port?: number;
		protocol?: string;
		headers?: Map<string, string>;
		dns?: DNSUDPOptions;
		onReadable?: (count: number, options?: WebSocketClientReadableOptions) => void;
		onWritable?: (count: number) => void;
		onControl?: (opcode: WebSocketClientOpcode, buffer: Uint8Array) => void; // should this be ArrayBuffer?
		onClose?: () => void;
		onError?: () => void;
	}

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
