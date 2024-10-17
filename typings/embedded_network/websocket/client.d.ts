declare module 'embedded:network/websocket/client' {
	import type { DNSUDPOptions } from 'embedded:network/dns/resolver/udp';
	import type { Buffer } from 'embedded:io/_common';
	import type TCP from 'embedded:io/socket/tcp';
	import type { TCPSocketOptions } from 'embedded:io/socket/tcp';
	import type TLSSocket from 'embedded:io/socket/tcp/tls';
	import type { TLSSocketOptions } from 'embedded:io/socket/tcp/tls';

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
		socket?: TCPSocketOptions | TLSSocketOptions;
		host?: string;
		port?: number;
		protocol?: string;
		headers?: Map<string, string>;
		dns?: DNSUDPOptions;		// spec says required, but when using attach it appears to be optional?
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
