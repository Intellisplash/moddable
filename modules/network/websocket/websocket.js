/*
 * Copyright (c) 2016-2024  Moddable Tech, Inc.
 *
 *   This file is part of the Moddable SDK Runtime.
 *
 *   The Moddable SDK Runtime is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Lesser General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   The Moddable SDK Runtime is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with the Moddable SDK Runtime.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*
	websocket client and server

	- validate Sec-WebSocket-Accept in client
*/

import { Socket, Listener } from 'socket';
import Logical from 'logical';
import { Digest } from 'crypt';
import Timer from 'timer';

// State tracks the state machine processing the protocol
const State = {
	connecting: 0, 		 // connection not yet started
	sendingHandshake: 1, // sending handshake status
	receivingHeaders: 2, // receiving handshake headers
	connected: 3, 		 // connected state, ready to send/receive messages
	disconnecting: 4,	 // close started, frame set and awaiting confirmation
	done: 5, 			 // connection terminated
};
Object.freeze(State.prototype);

// ReadState tracks partial reads to handle message fragmentation
const ReadState = {
	none: 0,			// no read in progress
	readLength: 1,		// read the length portion of the message
	readBuffer: 2,		// read the buffer portion of the message
};
Object.freeze(ReadState.prototype);

// Flags track the handshake header state
const Flags = {
	none: 0,
	upgrade: 1,
	accept: 2,
	version: 4,
	key: 8,
};
Object.freeze(Flags.prototype);

// the maximum length of a reason string in a close response message.  Any close response sent that
// is longer than this will be truncated to this length.  The size is arbitrary, but should be long
// enough for the message to be understandable, but short enough to avoid excessive buffer space
// allocation (and must be no more than 125 bytes to fit in the close frame header)
const MAX_RESPONSE_REASON_LENGTH = 50;

// the minimum amount of space that will be left in a Socket buffer to ensure we can fit headers and
// any message that we might need to send on-demand (thereby needing free space in the outgoing
// buffers to support it).  This is made up from the header size (2-byte frame header, 2-byte
// payload length, 4-byte masking key) plus the maximum size of a close response message (2-byte
// code plus MAX_RESPONSE_REASON_LENGTH bytes of reason)
const MIN_BUFFER_FREE_SPACE = 2 + 2 + 4 + 2 + MAX_RESPONSE_REASON_LENGTH;

const WSCloseCode = {
    NORMAL_CLOSURE: 1000,          // Connection closed normally, no error (network)
    GOING_AWAY: 1001,              // Endpoint is going away, such as server shutdown or client navigation (network)
    PROTOCOL_ERROR: 1002,          // Protocol error, e.g., invalid WebSocket frame (network)
    UNSUPPORTED_DATA: 1003,        // Received data that cannot be processed (network)
    // 1004 is reserved for future use and should not be used.
    NO_STATUS_RECEIVED: 1005,      // No status code received, used internally to indicate absence of a code (internal only)
    ABNORMAL_CLOSURE: 1006,        // Abnormal closure, used internally when connection closed without receiving a close frame (internal only)
    INVALID_FRAME_PAYLOAD_DATA: 1007, // Received invalid data, e.g., invalid UTF-8 (network)
    POLICY_VIOLATION: 1008,        // Termination due to policy violation, e.g., application-specific rule violation (network)
    MESSAGE_TOO_BIG: 1009,         // Message too big to process (network)
    MISSING_EXTENSION: 1010,       // Expected server to negotiate extensions, but they were not provided (network)
    INTERNAL_ERROR: 1011,          // Server encountered an unexpected condition preventing it from fulfilling the request (network)
    SERVICE_RESTART: 1012,         // Service is restarting, causing the connection to be closed (network)
    TRY_AGAIN_LATER: 1013,         // Server is temporarily unavailable, e.g., overload (network)
    BAD_GATEWAY: 1014,             // Server acting as a gateway received an invalid response from the upstream server (network)
    TLS_HANDSHAKE_FAILURE: 1015,   // Failure during the TLS handshake (internal only)
};

export class Client {
	constructor(dictionary) {
		// port, host, address, path (everything after port)
		this.path = dictionary.path ?? '/';
		this.host = dictionary.host ?? dictionary.address;
		this.headers = dictionary.headers ?? [];
		this.protocol = dictionary.protocol;

		if (dictionary.socket) {
			this.socket = dictionary.socket;
			this.isServer = true;
		}
		else {
			this.isServer = false;
			dictionary.port ??= 80;
			if (dictionary.Socket) {
				this.socket = new dictionary.Socket(Object.assign({}, dictionary.Socket, dictionary));
				// _log(this, 'Client using a custom Socket constructor');
			} else 
				this.socket = new Socket(dictionary);
		}
		this.socket.callback = clientSocketCallback.bind(this);

		// _log(this, `new Client(host ${this.host}, path ${this.path})`);
		this._setState(State.connecting);
        this._resetMessageState();
	}

	write(message) {
		if (message === undefined) return Math.max(this.socket.write() - MIN_BUFFER_FREE_SPACE, 0);

		const type = message instanceof ArrayBuffer ? 0x82 : 0x81;
		if (0x81 === type) message = ArrayBuffer.fromString(message);

		this._writeMessage(type, message);
	}

	_writeMessage(type, message) {
		const length = (typeof message === 'string') ? message.length : message.byteLength;

		if (length >= 65536) {
			this._resetMessageState();
			this._wrappedCallback?.(Client.error, "message too long");
			return;
		}

		let mask;
		if (!this.isServer) {
			// generate a "random" mask.  We use Math.random() (built on c_rand) which isn't highly
			// secure, but esp_random() is quite slow.  
			mask = new Uint8Array(4);
			// for (let i = 0; i < 4; i++) mask[i] = (Math.random() * 256) | 0;
			for (let i = 0; i < 4; i++) mask[i] = 0;
			// mask the message, which might be a string or a buffer
			if (typeof message === 'string') message = ArrayBuffer.fromString(message);
			Logical.xor(message, mask);

			if (length < 126)
				this._writeSocket(type, length | 0x80, mask, message);
			else
				this._writeSocket(type, 126 | 0x80, length >> 8, length & 0x0ff, mask, message);
		} else {
			if (length < 126)
				this._writeSocket(type, length, message);
			else
				this._writeSocket(type, 126, length >> 8, length & 0x0ff, message);
		}
	}
	_writeSocket(...args) {
		// _log(this, 'writeSocket: ', ...args);
		this.socket.write.apply(this.socket, args);
	}

	detach() {
		const socket = this.socket;
		delete this.socket.callback;
		delete this.socket;
		return socket;
	}
	close(code, reason, doNotReport) {
		if (!this.socket) return;
		if (code === undefined) code = WSCloseCode.NORMAL_CLOSURE;

		// if code isn't internal and we are connected, send the close frame
		if (
			code !== WSCloseCode.NO_STATUS_RECEIVED &&
			code !== WSCloseCode.ABNORMAL_CLOSURE && 
			code !== WSCloseCode.TLS_HANDSHAKE_FAILURE &&
			this.state === State.connected
		) {
			// _log(this, `> Client.close: Sending close frame, code ${code}, reason "${reason}"`);
			// set up the close frame
			let closeFrame;
			closeFrame = new Uint8Array(2 + (reason?.length ?? 0));
			closeFrame[0] = code >> 8;
			closeFrame[1] = code & 0xff;
			if (reason)
				for (let i = 0; i < reason.length; i++) closeFrame[i + 2] = reason.charCodeAt(i);

			try {
				this._writeMessage(0x88, closeFrame);
			} catch (e) {
				// _log(this, `>   Error sending close frame: ${e}`);
			}
			this._setState(State.disconnecting);
			return;
		}


		// tear it down...
		// _log(this, `> Client.close: Closing socket, code ${code}, state ${_stateMessage(this.state)}`);

		// report disconnect, but only if we have a socket (to handle case where the callback itself
		// throws an error and causes a closure as well, to avoid over-reporting the disconnect event)
		if (this.socket)
			this._wrappedCallback?.(Client.disconnect, { code, reason });

		// harden close, as we don't know the state of anything if this is happening post-error
			try {
			this.socket?.close();
		} catch {
			// _log(this, `Error closing client socket (ignoring)`);
		}
		delete this.socket;

		if (this.timer) Timer.clear(this.timer);
		delete this.timer;

		this._setState(State.done);
	}
	
	get(what) {
		if ('REMOTE_IP' === what) return this.socket.get('REMOTE_IP');
		return undefined;
	}

	set callback(cb) {
		this.origCallback = cb;
	}

	_wrappedCallback(reason, value) {
		return wrappedCallbackHandler(this, reason, value);
	}


	_setState(state) {
		// _log(this, `*   Set state to ${_stateMessage(state)}`);
		this.state = state;
	}

	_resetMessageState() {
		this.readState = ReadState.none;
		this.readTag = undefined;
		this.readLength = undefined;
		this.flags = Flags.none;
		this.byteCount = 0;
		this.readMaskBuffer = undefined;
		this.dataBuffer = undefined;
		this.captureBytes = 0;
		this.captureBuffer = undefined;
	}
}

function clientSocketCallback(message, socketByteCount) {
	let socket = this.socket;

    // _log(this, `CLIENT socket message: ${_socketMessage(message)}${message == Socket.readable ? ' (read ' + socketByteCount + ' bytes)' : ''}, state ${_stateMessage(this.state)}`);

	if (Socket.connected == message) {
		if (State.connecting != this.state) {
            this._resetMessageState();
			const reason = 'socket connected but ws not in connecting state';
            this._wrappedCallback?.(Client.error, reason);
			this.close(WSCloseCode.PROTOCOL_ERROR, reason);
			return;
        }

		this._wrappedCallback?.(Client.connect, this); // connected socket
		if (State.done === this.state) return;

		let key = new Uint8Array(16);
		for (let i = 0; i < 16; i++) key[i] = (Math.random() * 256) | 0;

		let response = [
			'GET ',
			this.path,
			' HTTP/1.1\r\n',
			'Host: ',
			this.host,
			'\r\n',
			'Upgrade: websocket\r\n',
			'Connection: keep-alive, Upgrade\r\n',
			'Sec-WebSocket-Version: 13\r\n',
			'Sec-WebSocket-Key: ',
			key.toBase64() + '\r\n',
		];

		if (this.protocol) response.push(`Sec-WebSocket-Protocol: ${this.protocol}\r\n`);

		let hdr = undefined;
		if (this.headers)
			for (let w of this.headers) {
				if (hdr === undefined) {
					hdr = w;
				} else {
					response.push(`${hdr}: ${w}\r\n`);
					hdr = undefined;
				}
			}
		if (hdr != undefined) {
			this._resetMessageState();
			const reason = 'invalid header array';
			this._wrappedCallback?.(Client.error, reason);
			this.close(WSCloseCode.INTERNAL_ERROR, reason);
			return;
		}

		response.push('\r\n');
		this._writeSocket(...response);

		delete this.path;
		delete this.host;
		delete this.headers;
		delete this.protocol;

		this._setState(State.sendingHandshake);
	}

	if (Socket.readable == message) {
		if (State.sendingHandshake === this.state) {
			let line = socket.read(String, '\n');
			socketByteCount -= line.length;

			if (this.line) {
				line = this.line + line;
				this.line = undefined;
			}

			if (10 != line.charCodeAt(line.length - 1)) {
				// partial header line, accumulate and wait for more
				this.line = line;
				return;
			}

			if ('HTTP/1.1 101' !== line.substring(0, 12)) {
                this._resetMessageState();
				const reason = 'HTTP error response';
				// _log(this, `    web socket upgrade failed: ${line.replace('\r\n', '')}`);
				this.close(WSCloseCode.PROTOCOL_ERROR, reason);
				return;
			}
			this._setState(State.receivingHeaders);
			this.line = undefined;
			this.flags = Flags.none;
		}
		if (State.receivingHeaders === this.state) {
			while (true) {
				if (socketByteCount == 0) return;
				let line = socket.read(String, '\n');
				socketByteCount -= line.length;

				if (this.line) {
					line = this.line + line;
					this.line = undefined;
				}

				if (10 != line.charCodeAt(line.length - 1)) {
					// partial header line, accumulate and wait for more
					this.line = line;
					return;
				}

				if ('\r\n' == line) {
					// empty line is end of headers
					if ((Flags.accept | Flags.upgrade | Flags.version) == this.flags) {
						this._setState(State.connected); // ready to receive
						this._wrappedCallback?.(Client.handshake); // websocket handshake complete
                        this._resetMessageState();
					} else {
						const reason = 'invalid header handshake';
						this._wrappedCallback?.(Client.error, reason);
						this.close(WSCloseCode.PROTOCOL_ERROR, reason);
						return;
					}
					delete this.flags;
					delete this.line;
					socketByteCount = socket.read(); // number of bytes available
					if (!socketByteCount) return;
					break;
				}

				let position = line.indexOf(':');
				let name = line.substring(0, position).trim().toLowerCase();
				let data = line.substring(position + 1).trim();

				if ('connection' == name) {
					if ('upgrade' == data.toLowerCase()) this.flags |= Flags.upgrade;
				} else if ('sec-websocket-accept' == name) {
					this.flags |= Flags.accept; //@@ validate data
				} else if ('upgrade' == name) {
					if ('websocket' == data.toLowerCase()) this.flags |= Flags.version;
				}
			}
		}
		if (State.connected === this.state || State.disconnecting === this.state) {
			// receive message
			// _log(this, `    Receive message, value ${socketByteCount}, read ${socket.read()}`);

			while (socketByteCount) {
				if (ReadState.none == this.readState) {
					if (this.readTag === undefined) {
						this.readTag = socket.read(Number);
						// _log(this, `    readTag is 0x${this.readTag.toString(16)} (tag ${this.readTag & 0x0f})`);
						--socketByteCount;
						continue;
					}
					if (this.readLength === undefined) {
						this.readLength = socket.read(Number);
						// _log(this, `    Length is ${this.readLength} (actual length ${this.readLength & 0x7f})`);
						--socketByteCount;
					}

					this.readMask = 0 != (this.readLength & 0x80);
					this.readLength &= 0x7f;
					if (126 == this.readLength) this.readState = ReadState.readLength;
					else if (127 == this.readLength) {
						// unsupported 8 byte length
						this._resetMessageState();
						const reason = 'unsupported 8 byte length';
						this._wrappedCallback?.(Client.error, reason);
						this.close(WSCloseCode.PROTOCOL_ERROR, reason);
						return;
					} else this.readState = ReadState.readBuffer;
					if (socketByteCount == 0) continue;
				}
				if (ReadState.readLength == this.readState) {
					// _log(this, '    Request length');
					// read length from next two bytes
					if (this.byteCount == 0) {
						this.readLength = socket.read(Number) << 8;
						socketByteCount--;
						++this.byteCount;
						continue;
					}
					if (this.byteCount == 1) {
						this.readLength |= socket.read(Number);
						socketByteCount--;
						this.byteCount = 0;
						// _log(this, `    Message indicates it has ${this.readLength} bytes in it`);
					}
					this.readState = ReadState.readBuffer;
				}
				if (ReadState.readBuffer == this.readState) {
					// if buffer read requested, allocate and reset the buffer index
					if (this.captureBytes > 0 && !this.captureBuffer) {
						this.captureBuffer = new Uint8Array(new ArrayBuffer(this.captureBytes));
						this.captureByteIndex = 0;
						// _log(this, `    Allocated buffer for reading`);
					}
					// if reading a buffer, keep going until all bytes satisified
					if (this.captureBuffer && this.captureBytes > 0) {
						while (socketByteCount > 0 && this.captureBytes > 0) {
							this.captureBuffer[this.captureByteIndex++] = socket.read(Number, 1);
							--socketByteCount;
							--this.captureBytes;
						}
						if (socketByteCount === 0 && this.captureBytes > 0) {
							// _log(this, `    Insufficient data, need another ${this.captureBytes} bytes`);
							return;
						}
					}

					// if a read mask is being used, get the four byte read mask into readMaskBuffer
					if (this.readMask && !this.readMaskBuffer) {
						if (!this.captureBuffer) {
							this.captureBytes = 4;
							// _log(this, `    Requesting 4 bytes for the read mask`);
							continue;
						}
						this.readMaskBuffer = this.captureBuffer.buffer;
						this.captureBuffer = undefined;
						// _log(this, `    Got the read mask`);
					}
					// if we have a read mask and the mask buffer, unmask the data
					if (this.readMask && this.readMaskBuffer && this.captureBuffer) 
						if (this.readMask) Logical.xor(this.captureBuffer.buffer, this.readMaskBuffer);


					// process the tag
					switch (this.readTag & 0x0f) {
					case 1: // text frame
					case 2: // binary frame
							if (!this.captureBuffer) {
								// _log(this, `    Request ${this.readLength} bytes for the data message`);
								this.captureBytes = this.readLength;
								continue;
							}
							// _log(this, `    Have buffer of ${this.captureBuffer.byteLength} bytes`);
							this.dataBuffer = this.captureBuffer.buffer;
							this.captureBuffer = undefined;

							if (1 === (this.readTag & 0x0f)) // text frame
								this.dataBuffer = String.fromArrayBuffer(this.dataBuffer);

							// _log(this, `    Sending callback with data`);
							this._wrappedCallback?.(Client.receive, this.dataBuffer);
							this._resetMessageState();
						break;
					case 8: // close frame
						if (!this.captureBuffer) {
							// _log(this, `    Request ${this.readLength} bytes for the close message`);
							this.captureBytes = this.readLength;
							continue;
						}

						const code = this.captureBuffer.byteLength >= 2 ? (this.captureBuffer[0] << 8 | this.captureBuffer[1]) : WSCloseCode.ABNORMAL_CLOSURE;
						const reason = this.captureBuffer.byteLength > 2 ? String.fromArrayBuffer(this.captureBuffer.slice(2).buffer) : '';
						
						// _log(this, `    Close frame received, code ${code}, reason "${reason}"`);

						// trigger close, which will send a close response if our state was connected
						this.close(code, reason);
						// if our state is disconnecting, we need to call close again to actually
						// close the socket as we handling the response not the request
						if (this.state === State.disconnecting) this.close(code, reason, true);

						return;
					case 9: // ping frame
						if (!this.captureBuffer && this.readLength) {
							this.captureBytes = this.readLength;
							continue;
						}
						this._writeMessage(0x8a, this.readLength ? this.captureBuffer.buffer : undefined);
						this._resetMessageState();
						break;
					case 10: // pong frame
							if (!this.captureBuffer) {
								this.captureBytes = this.readLength;
								continue;
							}
							this._resetMessageState();
						break;
					default:
						this.// _log(this, `> Unrecognized frame type: ${this.readTag & 0x0f}`);
							this._resetMessageState();
						break;
				    }
				}

				if (socketByteCount < 0) {
					message = Socket.error; // corrupt stream
					break;
				}
			}
		}
	}

	if (Socket.writable === message) {
		// data has been sent
		const bytesAvailable = Math.min(this.socket.write() - MIN_BUFFER_FREE_SPACE);
		// _log(this, `    Got datasent message, write says ${this.socket.write()} resulting in ${bytesAvailable} bytes available`);
		if (bytesAvailable > 0) 
			this._wrappedCallback?.(Client.datasent, bytesAvailable);
	}

	if (message < 0) {
		if (State.done !== this.state && State.disconnecting != this.state) {
			let reason;

			if (message === Socket.disconnected)
				reason = `unexpected socket disconnect`;
			else
				reason = `unknown socket error (code ${message})`;
			this._wrappedCallback?.(Client.error, reason);
			this.close(WSCloseCode.ABNORMAL_CLOSURE, reason);
		}
	}
}

export class Server {
	#listener;

	constructor(dictionary = {}) {
		if (null === dictionary.port) return;

		this.#listener = new Listener({ port: dictionary.port ?? 80 });
		this.#listener.callback = () => {
			// new client connection; create a new socket and provide the callers Server.callback
			// for to use once the handshake is done
			const request = addClient(new Socket({ listener: this.#listener }), State.sendingHandshake, this.origCallback);
			request._wrappedCallback?.(Server.connect, this); // tell app we have a new connection
		};
	}
	close(code, reason) {
		if (this.#listener) {
			this._wrappedCallback?.(Server.disconnect, { code, reason });
	
			this.#listener.callback = undefined;

			// harden close, as we don't know the state of anything if this is happening post-error
			try {
				this.#listener.close();
			} catch {
				// _log(this, `Error closing server socket (ignoring)`);
			}
			this.#listener = undefined;
		}
	}
	attach(socket) {
		const request = addClient(socket, State.receivingHeaders, this.origCallback);
		request.timer = Timer.set(() => {
			delete request.timer;
			request._wrappedCallback?.(Server.connect, this); // tell server app we have a new connection
			// trigger the callback to start reading the data
			socket._wrappedCallback?.(Socket.readable, socket.read());
		});
	}
	set callback(cb) {
		this.origCallback = cb;
	}
	_wrappedCallback(reason, value) {
		return wrappedCallbackHandler(this, reason, value);
	}
}

function addClient(socket, state, callback) {
	// create the new client object
	const request = new Client({ socket });
	socket.callback = serverSocketCallback.bind(request);
	request._setState(state);
	request.callback = callback; // set the Client callback to use the original Server.callback
	return request;
}

/*
	callback for server handshake, where 'this' is a Client object for the new connection (see addClient and
	Server.attach) after that, switches to client callback
*/
function serverSocketCallback(message, socketByteCount) {
	let socket = this.socket;

	if (!this.socket) return;

	// _log(this, `SERVER socket message: ${_socketMessage(message)}${message == Socket.readable ? ' (read ' + socketByteCount + ' bytes)' : ''}, state ${_stateMessage(this.state)}`);

	if (Socket.readable == message) {
		if (State.sendingHandshake === this.state || State.receivingHeaders === this.state) {
			while (true) {
				// oddly, socket.read with a terminator character exceptions if no data available
				if (socket.read() == 0) return;
				let line = socket.read(String, '\n');
				if (!line) return; // out of data. wait for more.

				if (this.line) {
					line = this.line + line;
					this.line = undefined;
				}

				if (10 != line.charCodeAt(line.length - 1)) {
					// partial header line, accumulate and wait for more
					this.line = line;
					return;
				}

				if ('\r\n' == line) {
					// empty line is end of headers
					if ((Flags.accept | Flags.upgrade | Flags.version | Flags.key) !== this.flags) {
                        this._resetMessageState();
						const reason = 'invalid handshake';
						this._wrappedCallback?.(Client.error, reason);
						this.close(WSCloseCode.PROTOCOL_ERROR, reason);
						return;
                    }

					delete this.line;
					delete this.flags;

					let sha1 = new Digest('SHA1');
					sha1.write(this.key);
					delete this.key;
					sha1.write('258EAFA5-E914-47DA-95CA-C5AB0DC85B11');

					let response = [
						'HTTP/1.1 101 Web Socket Protocol Handshake\r\n',
						'Connection: Upgrade\r\n',
						'Upgrade: websocket\r\n',
						'Sec-WebSocket-Accept: ',
						new Uint8Array(sha1.close()).toBase64(),
						'\r\n',
					];

					if (this.protocol) {
						response.push('Sec-WebSocket-Protocol: ', this.protocol, '\r\n');
						delete this.protocol;
					}
					response.push('\r\n');

					this._writeSocket(...response);
					// socket.write.apply(socket, response);

					this._wrappedCallback?.(Server.handshake); // websocket handshake complete

					this._setState(State.connected);
					socket.callback = clientSocketCallback.bind(this);
					socketByteCount = socket.read(); // number of bytes available
					if (0 !== socketByteCount) {
						// should be 0. unexpected to receive a websocket message before server receives handshake
						debugger;
						socket._wrappedCallback?.(2, socketByteCount);
					}
					return;
				}

				if (State.sendingHandshake === this.state) {
					// parse status line: GET / HTTP/1.1
					line = line.split(' ');
					if (line.length < 3) {
						this._resetMessageState();
						const reason = 'unknown status format';
						this._wrappedCallback?.(Client.error, reason);
						this.close(WSCloseCode.PROTOCOL_ERROR, reason);
						return;
					}
					if ('GET' != line[0]) {
						this._resetMessageState();
						const reason = 'not GET';
						this._wrappedCallback?.(Client.error, reason);
						this.close(WSCloseCode.PROTOCOL_ERROR, reason);
						return;
					}
					if ('HTTP/1.1' != line[line.length - 1].trim()) {
						this._resetMessageState();
						const reason = 'not HTTP/1.1';
						this._wrappedCallback?.(Client.error, reason);
						this.close(WSCloseCode.PROTOCOL_ERROR, reason);
						return;
					}
					//@@ could provide path to callback here
					this._setState(State.receivingHeaders);
					this.flags = Flags.none;
				} else if (State.receivingHeaders === this.state) {
					let position = line.indexOf(':');
					let name = line.substring(0, position).trim().toLowerCase();
					let data = line.substring(position + 1).trim();

					if ('upgrade' === name) this.flags |= data.toLowerCase() === 'websocket' ? Flags.upgrade : 0;
					else if ('connection' === name) {
						// Firefox: "Connection: keep-alive, Upgrade"
						data = data.split(',');
						for (let i = 0; i < data.length; i++)
							this.flags |= data[i].trim().toLowerCase() === 'upgrade' ? Flags.accept : 0;
					} else if ('sec-websocket-version' === name)
						this.flags |= data.toLowerCase() === '13' ? Flags.version : 0;
					else if ('sec-websocket-key' === name) {
						this.flags |= Flags.key;
						this.key = data;
					} else if ('sec-websocket-protocol' === name) {
						data = data.split(',');
						for (let i = 0; i < data.length; ++i) data[i] = data[i].trim().toLowerCase();
						const protocol = this._wrappedCallback?.(Server.subprotocol, data);
						if (protocol) this.protocol = protocol;
					}
				}
			}
		}
	}

	if (message < 0) {
		const reason = 'corrupt stream or socket error';
		this.close(WSCloseCode.PROTOCOL_ERROR, reason);
	}
}

function wrappedCallbackHandler(self, message, value) {
	if (!self.origCallback) {
		// _log(self, `Callback ignored; no callback defined: callback(${message}, ${value})`);
		return undefined;
	}
	// _log(self, `Callback: callback(${_callbackMessage(message)})`);

	return self.origCallback(message, value);
}

// function _log(self, ...args) {
// 	trace(`${self.isServer ? '<warn>' : '<info>'}WS ${self.isServer ? 'server' : 'client'}: `);

// 	for (const arg of args) {
// 		if (typeof arg === 'string') trace(`${arg.replace('\n', '\\n').replace('\r', '\\r')} `);
// 		else if (typeof arg == "object" && "byteLength" in arg) {
// 			const view = new Uint8Array(arg);
// 			for (const byte of view) trace(`0x${byte.toString(16)} `);
// 		} 
// 		else if (typeof arg === 'number') trace(`0x${arg.toString(16)} `);
// 		else trace('[unknown type typeof arg]');
// 	}
// 	trace('\n');
// }

// function _socketMessage(message) {
// 	switch (message) {
// 		case Socket.connected: return 'CONNECTED';
// 		case Socket.readable: return 'READABLE';
// 		case Socket.writable: return 'WRITABLE';
// 		case Socket.error: return 'ERROR';
// 		case Socket.disconnected: return 'DISCONNECTED';
// 		default: return `UNKNOWN (${message})`;
// 	}
// }

// function _stateMessage(state) {
// 	switch (state) {
// 		case State.connecting: return 'CONNECTING';
// 		case State.sendingHandshake: return 'SENDING-HANDSHAKE';
// 		case State.receivingHeaders: return 'RECEIVING-HEADERS';
// 		case State.connected: return 'CONNECTED';
// 		case State.disconnecting: return 'DISCONNECTING';
// 		case State.done: return 'DONE';
// 		default: return `UNKNOWN ${state}`;
// 	}
// }

// function _callbackMessage(message) {
// 	switch (message) {
// 		case Client.connect: return 'CONNECT';
// 		case Client.handshake: return 'HANDSHAKE';
// 		case Client.receive: return 'RECEIVE';
// 		case Client.disconnect: return 'DISCONNECT';
// 		case Server.subprotocol: return 'SUBPROTOCOL';
// 		case Client.datasent: return 'DATASENT';
// 		case Client.error: return 'ERROR';
// 		default: return `UNKNOWN ${message}`;
// 	}
// }


Server.connect = 1;
Server.handshake = 2;
Server.receive = 3;
Server.disconnect = 4;
Server.subprotocol = 5;
Object.freeze(Server.prototype);

Client.connect = 1;
Client.handshake = 2;
Client.receive = 3;
Client.disconnect = 4;
Client.datasent = 6;
Client.error = -1;
Object.freeze(Client.prototype);

export default Object.freeze({
	Client,
	Server,
});
