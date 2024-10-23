import System_ from "embedded:io/system"

declare global {
  // NOTE: `System` is non-standard and temporary to support the IO examples. Breaking changes are possible.
  var System: typeof System_;
  var device: Device;
}
