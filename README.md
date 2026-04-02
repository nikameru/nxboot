# nxboot

CLI tool for Nintendo Switch RCM payload launching (Fusée Gelée).
Powered by [Zig](ziglang.org) and [libusb](libusb.info).

## Requirements

- Zig 0.15.2

## Usage

1. Put the console in RCM and connect it via USB.
2. Run:
```sh
zig build -Doptimize=ReleaseSafe run -- /path/to/payload.bin
```

Note: with a Debug build (`-Doptimize=Debug`), the composed buffer is also written to `debug_payload.bin` in the current working directory.

## Credits

- @ktemkin (exploit discovery)
- Other implementations' authors

## Disclaimer

This software is for legitimate homebrew and recovery workflows on hardware you own. Misuse may void warranties or violate local law; you are responsible for compliance.
