# Installation and Security Guide
This guide explains how to install the `verifall` service as a systemd user service with security hardening.

## Requirements
* Go 1.22 or later
* Linux system with systemd installed
* User in the `tss` group for TPM access

## Building the Binary
### Update dependencies and build the binary
```
go get -u golang.org/x/crypto@latest
go mod tidy
go build
```

### Install the binary
```
sudo cp verifall /usr/local/bin/
sudo chown root:root /usr/local/bin/verifall
sudo chmod +x /usr/local/bin/verifall
```

## Device Access Setup
### Add your user to the appropriate groups based on your distribution
```
# On Fedora/RedHat systems:
sudo usermod -aG tss $USER

# On Ubuntu/Debian systems:
sudo usermod -aG tss,input $USER

# On some systems you might need a specific uhid group:
sudo groupadd -r uhid  # Create group if it doesn't exist
sudo usermod -aG uhid $USER
```

**Note: You'll need to log out and back in for these changes to take effect**

## Setting Up the Systemd User Service
This service should be installed as a user service, not as root:

1. Create the user service directory if it doesn't exist: `mkdir -p ~/.config/systemd/user/`
2. Copy the service file to the user directory: `cp verifall.service ~/.config/systemd/user/`
3. Reload systemd user daemon: `systemctl --user daemon-reload`
4. Enable and start the service: `systemctl --user enable --now verifall`
5. Check the service status: `systemctl --user status verifall`

## Security Configuration
The service creates a configuration directory at `~/.config/verifall/` with:
* `config.json`: Configuration settings including security options
* `credentials.json`: Database of keys

### Key Revocation
To revoke a compromised key, delete it (with its attributes) manually from `credentials.json`.

## Security Hardening Features
This implementation provides several security enhancements:
1. **Enhanced Security Logging**: Detailed security event tracking
2. **Input Validation**: Prevents various injection attacks
3. **Sandboxed Service**: Runs with minimal privileges

## Viewing Logs
* To view the user service logs: `journalctl --user -u verifall`
* To follow the logs in real-time: `journalctl --user -u verifall -f`

## Compromise Recovery
If you suspect a security compromise:
1. Stop the service: `systemctl --user stop verifall`
2. Remove key store: `rm ~/.config/verifall/credentials.json`
3. Restart the service: `systemctl --user start verifall`

## Uninstalling
To disable and stop the user service:
```
systemctl --user disable verifall
systemctl --user stop verifall
rm ~/.config/systemd/user/verifall.service
```

To remove the binary: `sudo rm /usr/local/bin/verifall`
