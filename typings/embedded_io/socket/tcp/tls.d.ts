declare module "embedded:io/socket/tcp/tls" {
	import { TCPOptions } from "embedded:io/socket/tcp";
	import UDP from "embedded:io/socket/udp";

	export type TLSOptions = TCPOptions & {
		host: string;
		secure: Record<string, any>; // should be called "tls" according to std?
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
