# verifidod

> **Note:** This project was forked from [psanford/tpm-fido](https://github.com/psanford/tpm-fido) and rewritten with enhanced security features.

verifidod is a FIDO token implementation for Linux that protects the token keys by using your system's TPM. verifidod uses Linux's [uhid](https://github.com/psanford/uhid) facility to emulate a USB HID device so that it is properly detected by browsers. It also authenticates with fprintd over DBUS for an additional layer of security.

##  Implementation details

verifidod uses the TPM 2.0 API and integrates with Linux's fprintd daemon for biometric authentication. The overall design is as follows:

On registration verifidod generates a new P256 primary key under the Owner hierarchy on the TPM. To ensure that the key is unique per site and registration, verifidod generates a random 20 byte seed for each registration. The primary key template is populated with unique values from a sha256 hkdf of the 20 byte random seed and the application parameter provided by the browser.

A signing child key is then generated from that primary key. The key handle returned to the caller is a concatenation of the child key's public and private key handles and the 20 byte seed.

On an authentication request, verifidod will attempt to load the primary key by initializing the hkdf in the same manner as above. It will then attempt to load the child key from the provided key handle. Any incorrect values or values created by a different TPM will fail to load.

In addition, every authentication and registration operation requires fingerprint verification through fprintd's DBUS interface, providing dual-factor authentication (TPM possession + biometric).

## Status

verifidod has been tested to work with Chrome and Firefox on Linux.

## Building

```
# in the root directory of verifidod run:
go build
```

## Running

In order to run `verifidod` you will need permission to access `/dev/tpmrm0`. On Ubuntu and Arch, you can add your user to the `tss` group.

Your user also needs permission to access `/dev/uhid` so that `verifidod` can appear to be a USB device.
I use the following udev rule to set the appropriate `uhid` permissions:

```
KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="SOME_UHID_GROUP_MY_USER_BELONGS_TO", MODE="0660"
```

To ensure the above udev rule gets triggered, I also add the `uhid` module to `/etc/modules-load.d/uhid.conf` so that it loads at boot.

Additionally, your user needs to be able to communicate with fprintd over DBUS, which typically requires membership in the `input` group.

To run:

```
# as a user that has permission to read and write to /dev/tpmrm0 and communicate with fprintd:
./verifidod
```
Note: do not run with `sudo` or as root, as it will not work.

## Dependencies

verifidod requires the following components:

- `pinentry` to be available on the system. If you have gpg installed you most likely already have `pinentry`.
- `fprintd` daemon running and configured with enrolled fingerprints
- A compatible fingerprint reader supported by fprintd