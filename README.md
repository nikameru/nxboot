# nxboot

CLI tool for Nintendo Switch RCM payload launching (Fusée Gelée). Uses Zig and libusb.

## Requirements

- Zig 0.15.2

## Usage

1. Put the console in RCM and connect it to your machine via USB.
2. Run:
```sh
zig build -Doptimize=ReleaseSafe run -- /path/to/payload.bin
```

Note: with a Debug build (`-Doptimize=Debug`), resulting RCM payload buffer is also written to `debug_payload.bin` in the current working directory.

## Credits

- @ktemkin (exploit discovery)
- Other implementations' authors
