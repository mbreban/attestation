# attestation

Package attestation implements ASN.1 encoding/decoding of Android Key attestation extension.

[![Go Reference](https://pkg.go.dev/badge/github.com/mbreban/attestation.svg)](https://pkg.go.dev/github.com/mbreban/attestation)

## Code example

```go
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/mbreban/attestation"
)

func main() {
	pemBytes := []byte(`
-----BEGIN CERTIFICATE-----
MIICjDCCAjKgAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAn
BgNVBAUTIDcwYzI5ODU2MGQ4ZTJlYmJjM2ViZTM5YmQ3NDc4ZDRjMB4XDTcwMDEw
MTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlz
dG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQR+vduzii4Rre8TkK3
12HzdLXxjojSCDXRUg9CISx7QjzBTvpmmsgZ5NCptZ0pX8umerf8H+xrrhL8R3y3
QvUyo4IBQzCCAT8wDgYDVR0PAQH/BAQDAgeAMIIBKwYKKwYBBAHWeQIBEQSCARsw
ggEXAgFkCgEBAgFkCgEBBAZzYW1wbGUEADBYv4U9CAIGAYDUNZXsv4VFSARGMEQx
HjAcBBdhcHAuYXR0ZXN0YXRpb24uYXVkaXRvcgIBLTEiBCCZDgTwhksZ8U+E4OQy
96OT8perEFoiweGxC0QqSmLELDCBpKEIMQYCAQICAQOiAwIBA6MEAgIBAKUFMQMC
AQSqAwIBAb+DdwIFAL+FPgMCAQC/hUBMMEoEIELtG8o1L6vUKPNOj87mJ3b0yyxm
4G+C5aWf9ElSZ7/CAQH/CgEABCC429249di4yi84SAUEJgb66JPihAI1gN+i3flu
dSP7hL+FQQUCAwHUwL+FQgUCAwMV3b+FTgYCBAE0ilm/hU8GAgQBNIpZMAoGCCqG
SM49BAMCA0gAMEUCIQDOefOPPwRmvyae6Yk/E4z0/7VKRyVH6mh+6ZPk84bTBAIg
CDxG2cHci7acvPave6jFDMt5GRpU4WG1SuZnBbEfr1A=
-----END CERTIFICATE-----`)

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("failed to decode certificate PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	ext := attestation.GetKeyExtension(cert)
	if ext == nil {
		log.Fatal("key attestation not found")
	}

	keyDesc, err := attestation.ParseExtension(ext.Value)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Got a %T\n", keyDesc)
	fmt.Printf("AttestationVersion: %q\n", keyDesc.AttestationVersion)
	fmt.Printf("AttestationSecurityLevel: %q\n", keyDesc.AttestationSecurityLevel)
	fmt.Printf("KeymasterVersion: %q\n", keyDesc.KeymasterVersion)
	fmt.Printf("KeymasterSecurityLevel: %q\n", keyDesc.KeymasterSecurityLevel)
	fmt.Printf("AttestationChallenge: %x (%s)\n", keyDesc.AttestationChallenge, keyDesc.AttestationChallenge)
	fmt.Printf("UniqueId: %x\n", keyDesc.UniqueId)
	fmt.Printf("SoftwareEnforced: %T\n", keyDesc.SoftwareEnforced)
	fmt.Printf("TeeEnforced: %T\n", keyDesc.TeeEnforced)
}
```

## Installation

Use `go get` to install the latest version of the package.

```sh
go get -u github.com/mbreban/attestation@latest
```

## CLI tool

`attestation-cli` is a command-line tool that prints the contents of the Key Attestation extension.

```sh
go install ./cmd/attestation-cli
attestation-cli parse -format der certificate.der.x509
```

## Testing

```sh
make test
```

## Resources

* https://source.android.com/docs/security/features/keystore/attestation
* https://source.android.com/docs/security/features/keystore/tags
* https://developer.android.com/privacy-and-security/security-key-attestation
* https://cs.android.com/android/platform/superproject/main/+/main:cts/tests/security/src/android/keystore/cts/Attestation.java
