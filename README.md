# RAuthp: Command line TOTP Generator 🔑

Rauthp is a CLI application for generating Time-based One-Time Passwords.
This tool uses DBus to store secrets in the user's keyring.

## Requirements 📋

- Rust 1.78.0 or higher
- A Keyring accessible via DBus (tested on GNOME)

## Build from sources ⚙️

Clone this repo and run

```sh
cargo build
```

## Getting started 🚀

```sh
rauthp -h # Print help
rauthp add 'Secret name' 'Base32 secret' # Store a secret in the keyring
rauthp gen # Generate the TOTP code for each secret
```

## Limitations

- Only supports SHA1
- Only tested with the GNOME keyring
- Developed to fit particular needs and probably doesn't cover every use case.