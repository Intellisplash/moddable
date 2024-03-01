/*
 * Copyright (c) 2021-2024  Moddable Tech, Inc.
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
    AM2320 - temp/humidity
    Datasheet: http://www.datasheet-pdf.com/PDF/AM2320-Datasheet-Aosong-952504

*/

import { CRC16 } from "crc";
import Timer from "timer";

const Register = Object.freeze({
	HUMID_MEASURE: 0x00,
	TEMP_MEASURE: 0x02,
	COMMAND_READ: 0x03
});

class AM2320  {
	#io;
	#valueBuffer = new Uint8Array(6);
	#cmdBuffer = this.#valueBuffer.subarray(0, 3);
	#crc = new CRC16(0x8005, 0xFFFF, true, true);

	constructor(options) {
		this.#io = new options.sensor.io({
			hz: 100_000,
			address: 0x5C,
			...options.sensor
		});
	}
	configure(/* options */) {
	}
	close() {
		this.#io?.close();
		this.#io = undefined;
	}
	sample() {
		const result = { hygrometer: {}, thermometer: {} };

		let humidity = this.#readValue(Register.HUMID_MEASURE);
		if (undefined !== humidity)
			result.hygrometer.humidity = (humidity / 10.0);

		let temperature = this.#readValue(Register.TEMP_MEASURE);
		if (undefined !== temperature) {
			if (temperature & 0x8000)
				temperature = -(temperature & 0x7fff);
			result.thermometer.temperature = (temperature / 10.0);
		}

		return result;
	}
	// retry and timing behavior based on https://github.com/adafruit/Adafruit_AM2320/blob/master/Adafruit_AM2320.cpp
	#readValue(reg) {
		const io = this.#io;
		const cmdBuffer = this.#cmdBuffer;
		const valueBuffer = this.#valueBuffer;

		// wake device
		for (let i = 0; i < 3; i++) {
			try {
				io.write(new ArrayBuffer(1));
				Timer.delay(10);
				break;
			}
			catch {
				if (2 === i)
					return;
				Timer.delay(100);
			}
		}

		// start conversion
		cmdBuffer[0] = Register.COMMAND_READ;
		cmdBuffer[1] = reg;
		cmdBuffer[2] = 0x02;
		for (let i = 0; i < 3; i++) {
			try {
				io.write(cmdBuffer);
				Timer.delay(2);
				break;
			}
			catch {
				if (2 === i)
					return;
				Timer.delay(5);
			}
		}

		// read data
		io.read(valueBuffer);

		// check crc
		this.#crc.reset();
		const crc = this.#crc.checksum(valueBuffer.subarray(0,4));
		if ((valueBuffer[5] != (crc >> 8)) || (valueBuffer[4] != (crc & 0xFF)))
			return;

		return (valueBuffer[2] << 8) | valueBuffer[3];
	}
}

export default AM2320;
