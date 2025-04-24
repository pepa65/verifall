# VerifidoD: TPM-Based FIDO Token for Linux with Dual-Factor Authentication

> **Note:** This project was forked from [psanford/tpm-fido](https://github.com/psanford/tpm-fido) and extensively refactored with enhanced security features including mandatory dual-factor authentication.

## Overview

VerifidoD is a FIDO2/U2F token implementation for Linux that secures authentication keys using your system's TPM (Trusted Platform Module) combined with fingerprint verification. It creates a virtual FIDO device using Linux's [uhid](https://github.com/psanford/uhid) facility, making it fully compatible with standard browsers.

### Key Security Features

- **Dual-Factor Authentication**: Requires both TPM possession (something you have) and fingerprint verification (something you are)
- **No Fallback Paths**: Both authentication factors are mandatory - there are no fallback or bypass options
- **Key Revocation**: Built-in ability to revoke compromised keys
- **Enhanced Logging**: Detailed security event tracking
- **Secure Configuration**: Hardened defaults prevent weakening security settings
- **Service Hardening**: Comprehensive systemd service hardening

## Implementation Details

VerifidoD implements a security-focused workflow that ensures proper authentication at every step:

### Registration Process

1. User initiates FIDO registration in their browser
2. VerifidoD requires fingerprint verification via fprintd
3. A unique P256 primary key is generated under the TPM Owner hierarchy
4. Each registration uses a random 20-byte seed combined with the application parameter
5. A signing child key is generated and securely stored in the TPM
6. The key handle returned contains necessary information to reload the key later

### Authentication Process

1. User initiates FIDO authentication in their browser
2. VerifidoD validates the key handle with the TPM
3. User must provide fingerprint verification via fprintd
4. Both factors must succeed - no exceptions
5. The TPM signs the challenge with the protected key
6. Signature is returned to the browser to complete authentication

## Status

VerifidoD has been tested with Chrome and Firefox on Linux. It implements the FIDO U2F protocol and works with websites supporting FIDO security keys.

## Installation

Please see the [INSTALL.md](INSTALL.md) file for detailed installation and configuration instructions.

### Build Requirements

- Go 1.22 or later
- TPM 2.0 device
- Fingerprint reader with enrolled fingerprints
- `pinentry` program (usually installed with GPG)
- Linux with systemd and fprintd installed

### Quick Build

```shell
go build
```

## Security Considerations

Please refer to [SECURITY.md](SECURITY.md) for a comprehensive security assessment and recommendations. The implemented security fixes include:

1. ✅ Updated dependencies to latest security-patched versions
2. ✅ Hardened authentication flow requiring both factors
3. ✅ Improved thread safety and race condition handling
4. ✅ Enhanced error handling and secure logging
5. ✅ Added input validation and defense-in-depth mechanisms
6. ✅ Implemented secure configuration management
7. ✅ Added service hardening measures

## System Configuration

### Required udev Rules

You must have proper udev rules in place for VerifidoD to access both your fingerprint reader and create the virtual FIDO device:

```
# /etc/udev/rules.d/70-fido.rules

# Goodix fingerprint reader WebAuthn access
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="27c6", ATTRS{idProduct}=="658c", TAG+="uaccess"

# Configure uhid permissions for TPM group access
KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="tss", MODE="0660"
```

After adding these rules, reload the udev rules and trigger them:

```shell
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Ensure your user belongs to the appropriate groups based on your distribution:

```shell
# On Fedora/RedHat systems:
sudo usermod -aG tss $USER

# On Ubuntu/Debian systems you might need:
sudo usermod -aG tss,input $USER

# On some systems you might need a specific uhid group:
sudo groupadd -r uhid  # Create group if it doesn't exist
sudo usermod -aG uhid $USER
```

**Note:** You'll need to log out and back in for group changes to take effect.

## Running as a Service

VerifidoD is designed to run as a user systemd service. Refer to [INSTALL.md](INSTALL.md) for complete setup instructions.

```shell
# Enable and start the service (after installation):
systemctl --user enable verifidod.service
systemctl --user start verifidod.service

# View service status:
systemctl --user status verifidod.service
```

## License

This project is licensed under the MIT License. 

Copyright (c) 2021 Peter Sanford (original author)  
Copyright (c) 2025 Scott Rushforth

See the [LICENSE](LICENSE) file for the full license text.
