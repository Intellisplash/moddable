declare module "embedded:io/socket/tcp/tls" {
  import { TCPSocketOptions as TCPOptions } from "embedded:io/socket/tcp"
  export type TLSSocketOptions = TCPOptions & {
    host: string
    secure: Record<string, any> // should be called "tls" according to std?
  }
  export default class TLSSocket {
    constructor(options: TLSSocketOptions) 
    close(): undefined
    read(count: number|ArrayBufferLike) : undefined|ArrayBufferLike
    write(buffer: ArrayBufferLike) : number
    set format(format: string) 
    get format() : string
  }
}

