# VerifidoD Installation and Security Guide

This guide explains how to install the VerifidoD service as a systemd user service with security hardening.

## Requirements

- Go 1.22 or later
- A TPM 2.0 device
- Fingerprint reader with enrolled fingerprints (Goodix readers supported by default)
- Linux system with systemd and fprintd installed
- User in the `tss` group for TPM access

## Building the Binary

1. Update dependencies and build the binary:
   ```
   go get -u github.com/google/go-tpm@latest
   go get -u golang.org/x/crypto@latest
   go get -u github.com/godbus/dbus/v5@latest
   go mod tidy
   go build
   ```

2. Copy the binary to `/usr/local/bin`:
   ```
   sudo cp verifidod /usr/local/bin/
   sudo chmod +x /usr/local/bin/verifidod
   ```

## Device Access Setup

1. Create a udev rules file for device access:
   ```
   sudo nano /etc/udev/rules.d/70-fido.rules
   ```

2. Add the following rules:
   ```
   # Goodix fingerprint reader WebAuthn access
   KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="27c6", ATTRS{idProduct}=="658c", TAG+="uaccess"

   # Configure uhid permissions for TPM group access
   KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="tss", MODE="0660"
   ```

3. Reload and apply the udev rules:
   ```
   sudo udevadm control --reload-rules
   sudo udevadm trigger
   ```

4. Add your user to the appropriate groups based on your distribution:
   ```
   # On Fedora/RedHat systems:
   sudo usermod -aG tss $USER

   # On Ubuntu/Debian systems you might need:
   sudo usermod -aG tss,input $USER

   # On some systems you might need a specific uhid group:
   sudo groupadd -r uhid  # Create group if it doesn't exist
   sudo usermod -aG uhid $USER
   ```
   *Note: You'll need to log out and back in for these changes to take effect*

## Fingerprint Authentication Setup

1. Verify your fingerprint reader is detected:
   ```
   fprintd-list
   ```

2. Enroll your fingerprints if not already done:
   ```
   fprintd-enroll
   ```

3. Verify your enrolled fingerprints:
   ```
   fprintd-list $USER
   ```

## Setting Up the Systemd User Service

This service should be installed as a user service, not as root:

1. Create the user service directory if it doesn't exist:
   ```
   mkdir -p ~/.config/systemd/user/
   ```

2. Copy the service file to the user directory:
   ```
   cp verifidod.service ~/.config/systemd/user/
   ```

3. Reload systemd user daemon:
   ```
   systemctl --user daemon-reload
   ```

4. Enable and start the service:
   ```
   systemctl --user enable verifidod.service
   systemctl --user start verifidod.service
   ```

5. Check the service status:
   ```
   systemctl --user status verifidod.service
   ```

> **Important Note**: The service must be run as a user service, not as root, to access TPM devices correctly. Running as root may cause permission issues.

## Security Configuration

The service creates a configuration directory at `~/.config/verifidod/` with:

- `config.json`: Configuration settings including security options
- `revoked_keys.json`: Database of revoked keys

### Key Revocation

To revoke a compromised key, use the command:
```
verifidod --revoke-key=<key-hash> --reason="Suspected compromise"
```

## Security Hardening Features

This implementation provides several security enhancements:

1. **Dual-Factor Authentication**: Both TPM and fingerprint verification are required
2. **No Fallback Authentication**: Authentication fails if either factor is unavailable
3. **Enhanced Security Logging**: Detailed security event tracking
4. **Key Revocation**: Ability to revoke compromised keys
5. **Input Validation**: Prevents various injection attacks
6. **Sandboxed Service**: Runs with minimal privileges

## Viewing Logs

To view the user service logs:
```
journalctl --user -u verifidod.service
```

To follow the logs in real-time:
```
journalctl --user -u verifidod.service -f
```

## Compromise Recovery

If you suspect a security compromise:

1. Stop the service:
   ```
   systemctl --user stop verifidod.service
   ```

2. Revoke all keys:
   ```
   verifidod --revoke-all
   ```

3. Re-enroll fingerprints:
   ```
   fprintd-delete $USER
   fprintd-enroll $USER
   ```

4. Restart the service:
   ```
   systemctl --user start verifidod.service
   ```

## Uninstalling

To disable and stop the user service:
```
systemctl --user disable verifidod.service
systemctl --user stop verifidod.service
rm ~/.config/systemd/user/verifidod.service
```

To remove the binary:
```
sudo rm /usr/local/bin/verifidod
```