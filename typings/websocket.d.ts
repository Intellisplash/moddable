/*
* Copyright (c) 2019-2020 Bradley Farias
*
*   This file is part of the Moddable SDK Tools.
*
*   The Moddable SDK Tools is free software: you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation, either version 3 of the License, or
*   (at your option) any later version.
*
*   The Moddable SDK Tools is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with the Moddable SDK Tools.  If not, see <http://www.gnu.org/licenses/>.
*
*/

declare module "websocket" {
  import type {TCPSocketOptions, ListenerOptions, Socket} from "socket";

  export type WebSocketClientOptions = TCPSocketOptions & {
    path?: string,
    protocol?: string,
    headers?: string[],
    socket?: Socket,
    Socket?: new (dict: { [k: string]: any; }) => unknown
  }

  export const enum WebSocketCloseCode {
    normal = 1000,
    goingAway = 1001,
    protocolError = 1002,
    unsupportedData = 1003,
    noStatus = 1005,
    abnormal = 1006,
    invalidData = 1007,
    policyViolation = 1008,
    tooLarge = 1009,
    extensionRequired = 1010,
    unexpectedCondition = 1011,
    tlsHandshake = 1015
  }

  export const enum WebSocketClientMessage {
    connect = 1,
    handshake = 2,
    receive = 3,
    disconnect = 4,
    datasent = 6,
    error = -1,
  }

  export type WSCloseArguments = { code: WebSocketCloseCode, reason?: string };

  export type WebSocketClientCallback =
    | ((message: WebSocketClientMessage.connect, server: Server) => void)
    | ((message: WebSocketClientMessage.disconnect, cause: WSCloseArguments) => void)
    | ((message: WebSocketClientMessage.receive, data: String | ArrayBuffer) => void)
    | ((message: WebSocketClientMessage.handshake) => void)
    | ((message: WebSocketClientMessage.datasent) => void)
    | ((message: WebSocketClientMessage.error, reason: string) => void);
  
  export class Client {
    static readonly connect: 1;
    static readonly handshake: 2;
    static readonly receive: 3;
    static readonly disconnect: 4;
    static readonly datasent: 6;
    static readonly error: -1;

    constructor(options: WebSocketClientOptions);
    close(code?: WebSocketCloseCode, reason?: string): void;
    write(data?: string | ArrayBuffer): number;
    callback: WebSocketClientCallback;
    detach(): Socket;
    readonly socket: Socket;
    get(what: 'REMOTE_IP'): string;
  }

  export const enum WebSocketServerMessage {
    connect = 1,
    handshake = 2,
    subprotocol = 5
  }

  export type WebSocketServerOptions = ListenerOptions
  // for the server callback, 'this' is bound to the Client instance
  export type WebSocketServerCallback = 
    | ((message: WebSocketServerMessage.connect, server: Server) => void)
    | ((message: WebSocketServerMessage.handshake) => void)
    | ((message: WebSocketServerMessage.subprotocol, subprotocol: string[]) => void);


  export class Server {
    static readonly connect: 1;
    static readonly handshake: 2;
    static readonly receive: 3; 
    static readonly disconnect: 4; 
    static readonly subprotocol: 5; 

    constructor(options: WebSocketServerOptions);
    close(): void;
    callback: WebSocketServerCallback;
    attach(socket: Socket): void;
  }
}