declare module "embedded:io/socket/tcp/tls" {
	import { TCPOptions } from "embedded:io/socket/tcp";
	import UDP from "embedded:io/socket/udp";

	export type SSLSessionOptions = {
		protocolVersion?: number;
		serverName?: string;
		applicationLayerProtocolNegotiation?: string;
		trace?: number;
		cache?: boolean;
		tls_server_name?: string;
		client_auth?: {
			cipherSuites: string[];
			subjectDN: string;
		};
	};

	export type TLSOptions = TCPOptions & {
		host: string;
		secure: SSLSessionOptions;
	};
	export type TLSDevice = TCPOptions & { io: typeof UDP };

	export default class TLSSocket {
		constructor(options: TLSOptions);
		close(): undefined;
		read(count: number | ArrayBufferLike): undefined | ArrayBufferLike;
		write(buffer: ArrayBufferLike): number;
		set format(format: string);
		get format(): string;
	}
}
