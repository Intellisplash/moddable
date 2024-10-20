/*
 * Copyright (c) 2020 Moddable Tech, Inc.
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

declare module 'pins/audioout' {
  type MixerSamples = 1;
  type MixerFlush = 2;
  type MixerCallback = 3;
  type MixerVolume = 4;
  type MixerRawSamples = 5;
  type MixerTone = 6;
  type MixerSilence = 7;
  type MixerKind = (
    MixerSamples |
    MixerFlush |
    MixerCallback |
    MixerVolume |
    MixerRawSamples |
    MixerTone |
    MixerSilence
  )
  type MixerOptions = {
    sampleRate?: number,
    bitsPerSample?: number,
    numChannels?: number,
    streams?: number,
  }
  
  export class Mixer {
    public constructor(options: MixerOptions)
    public close(): void
    public enqueue(stream: number, kind: MixerKind): void
    public enqueue(stream: number, kind: MixerKind, buffer: HostBuffer): void
    public enqueue(stream: number, kind: MixerCallback, value: number): void
    public enqueue(stream: number, kind: MixerKind, buffer: HostBuffer, repeat: number): void
    public enqueue(stream: number, kind: MixerKind, buffer: HostBuffer, repeat: number, offset: number): void
    public enqueue(stream: number, kind: MixerKind, buffer: HostBuffer, repeat: number, offset: number, count: number): void
    public enqueue(stream: number, kind: MixerTone, frequency: number, samples: number): void
    public enqueue(stream: number, kind: MixerSilence, samples: number): void
    public enqueue(stream: number, kind: MixerVolume, volume: number): void
    
    public mix(samplesNeeded: number): HostBuffer
    public mix(buffer: BufferLike): void

    public length(stream: number): number
  
    public readonly sampleRate: number
    public readonly bitsPerSample: number
    public readonly numChannels: number
    public readonly streams: number

    public static readonly Samples: MixerSamples
    public static readonly Flush: MixerFlush
    public static readonly Callback: MixerCallback
    public static readonly Volume: MixerVolume
    public static readonly RawSamples: MixerRawSamples
    public static readonly Tone: MixerTone
    public static readonly Silence: MixerSilence
  }

  type AudioOutCallback = (value: number) => void
  class AudioOut extends Mixer {
      start(): void
      stop(): void
      callback: AudioOutCallback
      callbacks: AudioOutCallback[]
      readonly mix: undefined
  }
  export { AudioOut as default }
}
