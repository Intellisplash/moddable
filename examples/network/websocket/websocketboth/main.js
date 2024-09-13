import { Server, Client } from "websocket";
import Timer from "timer";

// Define the MyServer class
class MyServer {
    constructor(port = 80) {
        this.server = new Server({ port });
        // Assign serverCallback without binding 'this'
        this.server.callback = this.serverCallback;
    }

    serverCallback(message, value) {
        switch (message) {
            case Server.connect:
                trace("Server: New connection received.\n");
                // 'this' is the Client instance from the library
                // Create a new MyClient instance for this connection
                new MyClient(this); // Pass the Client instance (socket)
                break;

            case Server.handshake:
                trace("Server: Handshake completed.\n");
                break;

            case Server.disconnect:
                trace("Server: Connection closed.\n");
                break;
        }
    }
}

// Define the MyClient class
class MyClient {
    constructor(options) {
        if (options instanceof Client) {
            // Server-side connection: options is the Client instance (socket)
            this.client = options;
            this.isServerSide = true;
        } else if (typeof options === 'object' && options.host) {
            // Client-side connection: options contains { host, path, port }
            this.client = new Client(options);
            this.isServerSide = false;
        } else {
            throw new Error('Invalid options for MyClient constructor');
        }

        // Bind clientCallback to maintain 'this' context
        this.client.callback = this.clientCallback.bind(this);

        // Initialize message counter
        this.messageCount = 0;
        this.maxMessages = 50; // Limit messages to prevent infinite loop
    }

    clientCallback(message, value) {
        switch (message) {
            case Client.connect:
                if (!this.isServerSide) {
                    trace("Client: Connected to server.\n");
                }
                break;

            case Client.handshake:
                trace(`Client: Handshake successful.  Available buffer is ${this.write()}\n`);
				debugger;
                if (!this.isServerSide) {
                    // Start the ping/pong loop by sending the first message
                    this.write("ping");
                }
                break;

            case Client.receive:
                trace(`Client (${this.isServerSide ? 'Server Side' : 'Client Side'}): Received message\n`);
				if (value === 'ping') {
					this.messageCount++;
					if (this.messageCount < this.maxMessages) {
						// Echo the received message back after a delay
						Timer.set(() => {
							for (let i = 0; i < 50; i++) {
								if (this.write() > 50)
									this.write("012345678901234567890123456789");
								else {
									trace(`STOP WRITE at ${i}, buffer available is ${this.write()}\n`);
									break;
								}
							}
							this.write('ping');
						});
					} else {
						// Close the connection after reaching max messages
						trace(`Client (${this.isServerSide ? 'Server Side' : 'Client Side'}): Max messages reached, closing connection.\n`);
						this.close();
					}
				}
                break;

            case Client.disconnect:
                trace("Client: Client disconnected.\n");
                break;
        }
    }

    write(data) {
        // Send data to the connected peer
        return this.client.write(data);
    }

    close() {
        // Close the WebSocket connection
        this.client.close();
    }
}

// Instantiate the server
new MyServer();

// Start a client connection to the server
new MyClient({ host: "localhost", path: "/", port: 80 });
