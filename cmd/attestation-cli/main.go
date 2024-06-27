package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/mbreban/attestation"
)

func fatalln(a ...any) {
	fmt.Fprintln(os.Stderr, a...)
	os.Exit(1)
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(1)
}

type Format string

func (f *Format) Set(val string) error {
	val = strings.ToUpper(val)

	switch val {
	case "PEM", "DER":
	default:
		return errors.New("PEM or DER expected")
	}

	*f = Format(val)

	return nil
}

func (f *Format) Get() any { return string(*f) }

func (f *Format) String() string { return fmt.Sprintf("%q", *f) }

type printer struct {
	w      io.StringWriter
	prefix string
	indent string
}

func (p *printer) Indent() {
	p.prefix = strings.TrimSuffix(p.prefix, p.indent)
}

func (p *printer) Outdent() {
	p.prefix += p.indent
}

func (p *printer) Printf(format string, a ...any) (n int, err error) {
	str := fmt.Sprintf(p.prefix+format, a...)
	return p.w.WriteString(str)
}

func main() {
	var output io.StringWriter = os.Stdout

	var format = Format("PEM")
	var jsonEncoded bool
	var out string

	flag.Var(&format, "format", "X.509 certificate format (one of PEM or DER)")
	flag.BoolVar(&jsonEncoded, "json", false, "Encode output in JSON format")
	flag.StringVar(&out, "out", "", "Output file")
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
	}

	if out != "" {
		f, err := os.Create(out)
		if err != nil {
			fatalln(err)
		}
		defer f.Close()

		output = f
	}

	for _, name := range flag.Args() {
		bytes, err := os.ReadFile(name)
		if err != nil {
			fatalln(err)
		}

		var crts []*x509.Certificate
		switch format.Get() {
		case "PEM":
			crts = parseCertsFromPEM(bytes)
		case "DER":
			crts, err = x509.ParseCertificates(bytes)
			if err != nil {
				fatalln(err)
			}
		}

		for i, crt := range crts {
			ext := attestation.GetKeyExtension(crt)
			if ext == nil {
				fatalf("failed to get key extension in %s\n", name)
			}

			keyDesc, err := attestation.ParseExtension(ext.Value)
			if err != nil {
				fatalln(err)
			}

			if jsonEncoded {
				data := struct {
					Name           string
					Index          int
					Subject        string
					KeyDescription *attestation.KeyDescription
				}{
					Name:           name,
					Index:          i,
					Subject:        crt.Subject.String(),
					KeyDescription: keyDesc,
				}

				raw, err := json.MarshalIndent(data, "", "  ")
				if err != nil {
					fatalln(err)
				}

				_, err = output.WriteString(string(raw))
				if err != nil {
					fatalln(err)
				}
			} else {
				printer := &printer{
					w:      output,
					prefix: "",
					indent: "  ",
				}

				printer.Printf("%s / %d / %q\n", name, i, crt.Subject.String())
				printKeyDescription(printer, keyDesc)
			}
		}
	}
}

func isNotEmpty(input interface{}) (interface{}, bool) {
	if input == nil || input == "" {
		return nil, false
	}

	v := reflect.ValueOf(input)
	if !v.IsValid() {
		return nil, false
	}

	switch v.Kind() {
	case reflect.Bool:
		return v.Bool(), !v.IsZero()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int(), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint(), true
	case reflect.Ptr:
		if v.IsNil() {
			return nil, false
		} else {
			return v.Elem().Interface(), true
		}
	case reflect.Map, reflect.Slice:
		return v, !v.IsNil()
	default:
		return nil, false
	}
}

func printKeyDescription(printer *printer, keyDesc *attestation.KeyDescription) {
	printer.Printf("AttestationVersion: %q (%d)\n", keyDesc.AttestationVersion.String(), keyDesc.AttestationVersion)
	printer.Printf("AttestationSecurityLevel: %q (%d)\n", keyDesc.AttestationSecurityLevel.String(), keyDesc.AttestationSecurityLevel)
	printer.Printf("KeymasterVersion: %q (%d)\n", keyDesc.KeymasterVersion.String(), keyDesc.KeymasterVersion)
	printer.Printf("KeymasterSecurityLevel: %q (%d)\n", keyDesc.KeymasterSecurityLevel.String(), keyDesc.KeymasterSecurityLevel)
	printer.Printf("AttestationChallenge: %x (%s)\n", keyDesc.AttestationChallenge, keyDesc.AttestationChallenge)
	printer.Printf("UniqueId: %x\n", keyDesc.UniqueId)

	printer.Printf("SoftwareEnforced:\n")
	printAuthorizationList(printer, keyDesc.SoftwareEnforced)

	printer.Printf("TeeEnforced:\n")
	printAuthorizationList(printer, keyDesc.TeeEnforced)
}

func printAuthorizationList(printer *printer, in attestation.AuthorizationList) {
	printer.Outdent()
	defer printer.Indent()

	if v, ok := isNotEmpty(in.Algorithm); ok {
		printer.Printf("Algorithm: %v (%d)\n", v, v)
	}
	if _, ok := isNotEmpty(in.Purpose); ok {
		printer.Printf("Purpose: %v\n", in.Purpose)
	}
	if v, ok := isNotEmpty(in.KeySize); ok {
		printer.Printf("KeySize: %v\n", v)
	}
	if _, ok := isNotEmpty(in.Digest); ok {
		printer.Printf("Digest: %v\n", in.Digest)
	}
	if _, ok := isNotEmpty(in.Padding); ok {
		printer.Printf("Padding: %v\n", in.Padding)
	}
	if v, ok := isNotEmpty(in.EcCurve); ok {
		printer.Printf("EcCurve: %v (%d)\n", v, v)
	}
	if v, ok := isNotEmpty(in.RsaPublicExponent); ok {
		printer.Printf("RsaPublicExponent: %v\n", v)
	}
	if _, ok := isNotEmpty(in.RollbackResistance); ok {
		printer.Printf("RollbackResistance: %t\n", in.RollbackResistance)
	}
	if _, ok := isNotEmpty(in.ActiveDateTime); ok {
		printer.Printf("ActiveDateTime: %v\n", in.ActiveDateTime)
	}
	if _, ok := isNotEmpty(in.OriginationExpireDateTime); ok {
		printer.Printf("OriginationExpireDateTime: %v\n", in.OriginationExpireDateTime)
	}
	if _, ok := isNotEmpty(in.UsageExpireDateTime); ok {
		printer.Printf("UsageExpireDateTime: %v\n", in.UsageExpireDateTime)
	}
	if _, ok := isNotEmpty(in.NoAuthRequired); ok {
		printer.Printf("NoAuthRequired: %t\n", in.NoAuthRequired)
	}
	if _, ok := isNotEmpty(in.UserAuthType); ok {
		printer.Printf("UserAuthType: %v\n", in.UserAuthType)
	}
	if v, ok := isNotEmpty(in.AuthTimeout); ok {
		printer.Printf("AuthTimeout: %v\n", v)
	}
	if _, ok := isNotEmpty(in.AllowWhileOnBody); ok {
		printer.Printf("AllowWhileOnBody: %t\n", in.AllowWhileOnBody)
	}
	if _, ok := isNotEmpty(in.TrustedUserPresenceRequired); ok {
		printer.Printf("TrustedUserPresenceRequired: %t\n", in.TrustedUserPresenceRequired)
	}
	if _, ok := isNotEmpty(in.TrustedConfirmationRequired); ok {
		printer.Printf("TrustedConfirmationRequired: %t\n", in.TrustedConfirmationRequired)
	}
	if _, ok := isNotEmpty(in.UnlockedDeviceRequired); ok {
		printer.Printf("UnlockedDeviceRequired: %t\n", in.UnlockedDeviceRequired)
	}
	if _, ok := isNotEmpty(in.AllApplications); ok {
		printer.Printf("AllApplications: %t\n", in.AllApplications)
	}
	if _, ok := isNotEmpty(in.ApplicationId); ok {
		printer.Printf("ApplicationId: %s\n", in.ApplicationId)
	}
	if v, ok := isNotEmpty(in.CreationDateTime); ok {
		printer.Printf("CreationDateTime: %v\n", v)
	}
	if v, ok := isNotEmpty(in.Origin); ok {
		printer.Printf("Origin: %v (%d)\n", v, v)
	}
	if _, ok := isNotEmpty(in.RollbackResistant); ok {
		printer.Printf("RollbackResistant: %t\n", in.RollbackResistant)
	}

	if in.RootOfTrust != nil {
		printer.Printf("RootOfTrust:\n")
		printRootOfTrust(printer, in.RootOfTrust)
	}

	if v, ok := isNotEmpty(in.OsVersion); ok {
		printer.Printf("OsVersion: %v\n", v)
	}
	if v, ok := isNotEmpty(in.OsPatchLevel); ok {
		printer.Printf("OsPatchLevel: %v\n", v)
	}

	if in.AttestationApplicationId != nil {
		printer.Printf("AttestationApplicationId:\n")
		printAttestationApplicationId(printer, in.AttestationApplicationId)
	}

	if _, ok := isNotEmpty(in.AttestationIdBrand); ok {
		printer.Printf("AttestationIdBrand: %s\n", in.AttestationIdBrand)
	}
	if _, ok := isNotEmpty(in.AttestationIdDevice); ok {
		printer.Printf("AttestationIdDevice: %s\n", in.AttestationIdDevice)
	}
	if _, ok := isNotEmpty(in.AttestationIdProduct); ok {
		printer.Printf("AttestationIdProduct: %s\n", in.AttestationIdProduct)
	}
	if _, ok := isNotEmpty(in.AttestationIdSerial); ok {
		printer.Printf("AttestationIdSerial: %s\n", in.AttestationIdSerial)
	}
	if _, ok := isNotEmpty(in.AttestationIdImei); ok {
		printer.Printf("AttestationIdImei: %s\n", in.AttestationIdImei)
	}
	if _, ok := isNotEmpty(in.AttestationIdMeid); ok {
		printer.Printf("AttestationIdMeid: %s\n", in.AttestationIdMeid)
	}
	if _, ok := isNotEmpty(in.AttestationIdManufacturer); ok {
		printer.Printf("AttestationIdManufacturer: %s\n", in.AttestationIdManufacturer)
	}
	if _, ok := isNotEmpty(in.AttestationIdModel); ok {
		printer.Printf("AttestationIdModel: %s\n", in.AttestationIdModel)
	}
	if v, ok := isNotEmpty(in.VendorPatchLevel); ok {
		printer.Printf("VendorPatchLevel: %v\n", v)
	}
	if v, ok := isNotEmpty(in.BootPatchLevel); ok {
		printer.Printf("BootPatchLevel: %v\n", v)
	}
}

func printRootOfTrust(printer *printer, rot *attestation.RootOfTrust) {
	printer.Outdent()
	defer printer.Indent()

	printer.Printf("VerifiedBootKey: %x\n", rot.VerifiedBootKey)
	printer.Printf("DeviceLocked: %t\n", rot.DeviceLocked)
	printer.Printf("VerifiedBootState: %q (%d)\n", rot.VerifiedBootState.String(), rot.VerifiedBootState)
	printer.Printf("VerifiedBootHash: %x\n", rot.VerifiedBootHash)
}

func printAttestationApplicationId(printer *printer, appId *attestation.AttestationApplicationId) {
	printer.Outdent()
	defer printer.Indent()

	for _, app := range appId.PackageInfos {
		printer.Printf("PackageName: %s\n", app.PackageName)
		printer.Printf("Version: %d\n", app.Version)
	}
	printer.Printf("SignatureDigests: %x\n", appId.SignatureDigests)
}

// parseCertsFromPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates were successfully parsed.
//
// Based on https://golang.org/pkg/crypto/x509/#CertPool.AppendCertsFromPEM.
func parseCertsFromPEM(pemCerts []byte) []*x509.Certificate {
	var certs []*x509.Certificate

	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		certBytes := block.Bytes
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}

		certs = append(certs, cert)
	}

	return certs
}
