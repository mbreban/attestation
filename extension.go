package attestation

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var errNoData = errors.New("attestation: no data")

func newInt(v asn1.RawValue, a any) error {
	if len(v.Bytes) == 0 {
		return errNoData
	}

	if rest, err := asn1.Unmarshal(v.Bytes, a); err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("attestation: trailing data after Integer")
	}

	return nil
}

func newOptionnalInt(v asn1.RawValue) (*int, error) {
	var i int
	if err := newInt(v, &i); err != nil {
		if err == errNoData {
			return nil, nil
		}
		return nil, err
	}
	return &i, nil
}

func newOptionnalInt32(v asn1.RawValue) (*int32, error) {
	var i int32
	if err := newInt(v, &i); err != nil {
		if err == errNoData {
			return nil, nil
		}
		return nil, err
	}
	return &i, nil
}

func newOptionnalInt64(v asn1.RawValue) (*int64, error) {
	var i int64
	if err := newInt(v, &i); err != nil {
		if err == errNoData {
			return nil, nil
		}
		return nil, err
	}
	return &i, nil
}

func newIntRawValue(v *int, tag int) (asn1.RawValue, error) {
	if v == nil {
		return asn1.RawValue{}, nil
	}
	return newAnyRawValue(*v, tag)
}

func newInt32RawValue(v *int32, tag int) (asn1.RawValue, error) {
	if v == nil {
		return asn1.RawValue{}, nil
	}
	return newAnyRawValue(*v, tag)
}

func newInt64RawValue(v *int64, tag int) (asn1.RawValue, error) {
	if v == nil {
		return asn1.RawValue{}, nil
	}
	return newAnyRawValue(*v, tag)
}

func newAnyRawValue(v any, tag int) (asn1.RawValue, error) {
	derBytes, err := asn1.Marshal(v)
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: derBytes}, nil
}

func newBoolRawValue(v bool, tag int) asn1.RawValue {
	if v {
		return asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        tag,
			IsCompound: true,
			Bytes:      asn1.NullBytes,
		}
	}
	return asn1.RawValue{}
}

func createAuthorizationList(authList *AuthorizationList) (*authorizationList, error) {
	var al authorizationList
	var err error

	if authList == nil {
		return nil, errors.New("attestation: AuthorizationList is nil")
	}

	if c := authList.EcCurve; c != nil {
		v := (int)(*c)
		al.EcCurve, err = newAnyRawValue(v, TagEcCurve)
		if err != nil {
			return nil, err
		}
	}

	al.RsaPublicExponent, err = newInt64RawValue(authList.RsaPublicExponent, TagRsaPublicExponent)
	if err != nil {
		return nil, err
	}

	var purposes []int32
	for _, purpose := range authList.Purpose {
		purposes = append(purposes, int32(purpose))
	}
	al.Purpose = purposes

	if a := authList.Algorithm; a != nil {
		v := (int32)(*a)
		al.Algorithm, err = newAnyRawValue(v, TagAlgorithm)
		if err != nil {
			return nil, err
		}
	}
	al.KeySize, err = newIntRawValue(authList.KeySize, TagKeySize)
	if err != nil {
		return nil, err
	}

	var digests []int
	for _, digest := range authList.Digest {
		digests = append(digests, int(digest))
	}
	al.Digest = digests

	var paddings []int
	for _, padding := range authList.Padding {
		paddings = append(paddings, int(padding))
	}
	al.Padding = paddings

	al.RollbackResistance = newBoolRawValue(authList.RollbackResistance, TagRollbackResistance)
	al.ActiveDateTime, err = newInt64RawValue(authList.ActiveDateTime, TagActiveDateTime)
	if err != nil {
		return nil, err
	}
	al.OriginationExpireDateTime, err = newIntRawValue(authList.OriginationExpireDateTime, TagOriginationExpireDateTime)
	if err != nil {
		return nil, err
	}
	al.UsageExpireDateTime, err = newInt64RawValue(authList.UsageExpireDateTime, TagUsageExpireDateTime)
	if err != nil {
		return nil, err
	}
	al.NoAuthRequired = newBoolRawValue(authList.NoAuthRequired, TagNoAuthRequired)

	if t := authList.UserAuthType; t != nil {
		v := (int32)(*t)
		al.UserAuthType, err = newAnyRawValue(v, TagUserAuthType)
		if err != nil {
			return nil, err
		}
	}

	al.AuthTimeout, err = newInt32RawValue(authList.AuthTimeout, TagAuthTimeout)
	if err != nil {
		return nil, err
	}
	al.AllowWhileOnBody = newBoolRawValue(authList.AllowWhileOnBody, TagAllowWhileOnBody)
	al.TrustedUserPresenceRequired = newBoolRawValue(authList.TrustedUserPresenceRequired, TagTrustedUserPresenceRequired)
	al.TrustedConfirmationRequired = newBoolRawValue(authList.TrustedConfirmationRequired, TagTrustedConfirmationRequired)
	al.UnlockedDeviceRequired = newBoolRawValue(authList.UnlockedDeviceRequired, TagUnlockedDeviceRequired)
	al.AllApplications = newBoolRawValue(authList.AllApplications, TagAllApplications)
	al.ApplicationId = authList.ApplicationId
	al.CreationDateTime, err = newIntRawValue(authList.CreationDateTime, TagCreationDateTime)
	if err != nil {
		return nil, err
	}

	if o := authList.Origin; o != nil {
		v := (int)(*o)
		al.Origin, err = newAnyRawValue(v, TagOrigin)
		if err != nil {
			return nil, err
		}
	}

	al.RollbackResistant = newBoolRawValue(authList.RollbackResistant, TagRollbackResistant)

	if authList.RootOfTrust != nil {
		rotDerBytes, err := marshalRoT(authList.RootOfTrust)
		if err != nil {
			return nil, err
		}
		al.RootOfTrust = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: TagRootOfTrust, IsCompound: true, Bytes: rotDerBytes}
	}

	al.OsVersion, err = newIntRawValue(authList.OsVersion, TagOsVersion)
	if err != nil {
		return nil, err
	}
	al.OsPatchLevel, err = newIntRawValue(authList.OsPatchLevel, TagOsPatchLevel)
	if err != nil {
		return nil, err
	}

	if authList.AttestationApplicationId != nil {
		appIdBytes, err := marshalAttestationApplicationId(authList.AttestationApplicationId)
		if err != nil {
			return nil, err
		}
		al.AttestationApplicationId = asn1.RawContent(appIdBytes)
	}

	al.AttestationIdBrand = authList.AttestationIdBrand
	al.AttestationIdDevice = authList.AttestationIdDevice
	al.AttestationIdProduct = authList.AttestationIdProduct
	al.AttestationIdSerial = authList.AttestationIdSerial
	al.AttestationIdImei = authList.AttestationIdImei
	al.AttestationIdMeid = authList.AttestationIdMeid
	al.AttestationIdManufacturer = authList.AttestationIdManufacturer
	al.AttestationIdModel = authList.AttestationIdModel

	al.VendorPatchLevel, err = newIntRawValue(authList.VendorPatchLevel, TagVendorPatchLevel)
	if err != nil {
		return nil, err
	}
	al.BootPatchLevel, err = newIntRawValue(authList.BootPatchLevel, TagBootPatchLevel)
	if err != nil {
		return nil, err
	}

	return &al, nil
}

// CreateExtension creates a new KeyDescription based on a template.
func CreateKeyDescription(template *KeyDescription) ([]byte, error) {
	if template == nil {
		return nil, errors.New("attestation: template is nil")
	}

	var keyDesc keyDescription
	keyDesc.AttestationVersion = int(template.AttestationVersion)
	keyDesc.AttestationSecurityLevel = asn1.Enumerated(template.AttestationSecurityLevel)
	keyDesc.KeymasterVersion = int(template.KeymasterVersion)
	keyDesc.KeymasterSecurityLevel = asn1.Enumerated(template.KeymasterSecurityLevel)
	keyDesc.AttestationChallenge = template.AttestationChallenge
	keyDesc.UniqueId = template.UniqueId

	authorizationList, err := createAuthorizationList(&template.SoftwareEnforced)
	if err != nil {
		return nil, err
	}
	keyDesc.SoftwareEnforced = asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      authorizationList.Raw,
	}

	authorizationList, err = createAuthorizationList(&template.TeeEnforced)
	if err != nil {
		return nil, err
	}
	keyDesc.TeeEnforced = asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      authorizationList.Raw,
	}

	derBytes, err := asn1.Marshal(keyDesc)
	if err != nil {
		return nil, fmt.Errorf("attestation: %v", err)
	}

	return derBytes, nil
}

// CreateExtension creates a new Attestation extension based on a template.
func CreateExtension(template *KeyDescription) (*pkix.Extension, error) {
	derBytes, err := CreateKeyDescription(template)
	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Id:    OIDKeyAttestationExtension,
		Value: derBytes,
	}, nil
}

// ParseExtension parses a single KeyDescription from the given ASN.1 DER data.
func ParseExtension(derBytes []byte) (*KeyDescription, error) {
	var keyDesc keyDescription
	if rest, err := asn1.Unmarshal(derBytes, &keyDesc); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("attestation: trailing data after KeyDescription")
	}
	return parseKeyDescription(&keyDesc)
}

func parseAuthorizationList(derBytes []byte) (*authorizationList, error) {
	var authList authorizationList
	if rest, err := asn1.Unmarshal(derBytes, &authList); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("attestation: trailing data after AuthorizationList")
	}
	return &authList, nil
}

func newAuthorizationList(in *authorizationList) (*AuthorizationList, error) {
	var out = &AuthorizationList{}
	var err error

	out.Raw = in.Raw

	if a, err := newOptionnalInt(in.Algorithm); err != nil {
		return nil, err
	} else if a != nil {
		v := new(Algorithm)
		*v = (Algorithm)(*a)
		out.Algorithm = v
	}

	if c, err := newOptionnalInt(in.EcCurve); err != nil {
		return nil, err
	} else if c != nil {
		v := new(EcCurve)
		*v = EcCurve(*c)
		out.EcCurve = v
	}

	out.RsaPublicExponent, err = newOptionnalInt64(in.RsaPublicExponent)
	if err != nil {
		return nil, err
	}
	out.KeySize, err = newOptionnalInt(in.KeySize)
	if err != nil {
		return nil, err
	}

	for _, d := range in.Digest {
		out.Digest = append(out.Digest, Digest(d))
	}

	for _, m := range in.Padding {
		out.Padding = append(out.Padding, PaddingMode(m))
	}

	for _, p := range in.Purpose {
		out.Purpose = append(out.Purpose, KeyPurpose(p))
	}

	out.RollbackResistance = isNullType(in.RollbackResistance)
	out.ActiveDateTime, err = newOptionnalInt64(in.ActiveDateTime)
	if err != nil {
		return nil, err
	}
	out.OriginationExpireDateTime, err = newOptionnalInt(in.OriginationExpireDateTime)
	if err != nil {
		return nil, err
	}
	out.UsageExpireDateTime, err = newOptionnalInt64(in.UsageExpireDateTime)
	if err != nil {
		return nil, err
	}
	out.NoAuthRequired = isNullType(in.NoAuthRequired)

	if t, err := newOptionnalInt32(in.UserAuthType); err != nil {
		return nil, err
	} else if t != nil {
		v := new(HardwareAuthenticatorType)
		*v = HardwareAuthenticatorType(*t)
		out.UserAuthType = v
	}

	out.AuthTimeout, err = newOptionnalInt32(in.AuthTimeout)
	if err != nil {
		return nil, err
	}
	out.AllowWhileOnBody = isNullType(in.AllowWhileOnBody)
	out.TrustedUserPresenceRequired = isNullType(in.TrustedUserPresenceRequired)
	out.TrustedConfirmationRequired = isNullType(in.TrustedConfirmationRequired)
	out.UnlockedDeviceRequired = isNullType(in.UnlockedDeviceRequired)
	out.AllApplications = isNullType(in.AllApplications)
	out.ApplicationId = in.ApplicationId
	out.CreationDateTime, err = newOptionnalInt(in.CreationDateTime)
	if err != nil {
		return nil, err
	}

	if o, err := newOptionnalInt(in.Origin); err != nil {
		return nil, err
	} else if o != nil {
		v := new(KeyOrigin)
		*v = (KeyOrigin)(*o)
		out.Origin = v
	}

	out.RollbackResistant = isNullType(in.RollbackResistant)

	if in.RootOfTrust.FullBytes != nil {
		rot, err := parseRootOfTrust(in.RootOfTrust.Bytes)
		if err != nil {
			return nil, fmt.Errorf("RootOfTrust: %v", err)
		}
		out.RootOfTrust = rot
	}

	out.OsVersion, err = newOptionnalInt(in.OsVersion)
	if err != nil {
		return nil, err
	}
	out.OsPatchLevel, err = newOptionnalInt(in.OsPatchLevel)
	if err != nil {
		return nil, err
	}

	if in.AttestationApplicationId != nil {
		attestationApplicationId, err := parseAttestationApplicationId(in.AttestationApplicationId)
		if err != nil {
			return nil, fmt.Errorf("AttestationApplicationId: %v", err)
		}

		app := &AttestationApplicationId{
			SignatureDigests: attestationApplicationId.SignatureDigests,
		}

		for _, p := range attestationApplicationId.PackageInfos {
			pkg := &AttestationPackageInfo{
				PackageName: string(p.PackageName),
				Version:     p.Version,
			}
			app.PackageInfos = append(app.PackageInfos, pkg)
		}

		out.AttestationApplicationId = app
	}

	out.AttestationIdBrand = in.AttestationIdBrand
	out.AttestationIdDevice = in.AttestationIdDevice
	out.AttestationIdProduct = in.AttestationIdProduct
	out.AttestationIdSerial = in.AttestationIdSerial
	out.AttestationIdImei = in.AttestationIdImei
	out.AttestationIdMeid = in.AttestationIdMeid
	out.AttestationIdManufacturer = in.AttestationIdManufacturer
	out.AttestationIdModel = in.AttestationIdModel
	out.VendorPatchLevel, err = newOptionnalInt(in.VendorPatchLevel)
	if err != nil {
		return nil, err
	}
	out.BootPatchLevel, err = newOptionnalInt(in.BootPatchLevel)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func parseKeyDescription(in *keyDescription) (*KeyDescription, error) {
	var out = &KeyDescription{
		Raw:                      in.Raw,
		AttestationVersion:       AttestationVersion(in.AttestationVersion),
		AttestationSecurityLevel: SecurityLevel(in.AttestationSecurityLevel),
		KeymasterVersion:         KeymasterVersion(in.KeymasterVersion),
		KeymasterSecurityLevel:   SecurityLevel(in.KeymasterSecurityLevel),
		AttestationChallenge:     in.AttestationChallenge,
		UniqueId:                 in.UniqueId,
	}

	softwareEnforced, err := parseAuthorizationList(in.SoftwareEnforced.FullBytes)
	if err != nil {
		return nil, err
	}
	authorizationList, err := newAuthorizationList(softwareEnforced)
	if err != nil {
		return nil, fmt.Errorf("attestation: %v", err)
	}
	out.SoftwareEnforced = *authorizationList

	teeEnforced, err := parseAuthorizationList(in.TeeEnforced.FullBytes)
	if err != nil {
		return nil, err
	}
	authorizationList, err = newAuthorizationList(teeEnforced)
	if err != nil {
		return nil, fmt.Errorf("attestation: %v", err)
	}
	out.TeeEnforced = *authorizationList

	return out, nil
}

func parseRootOfTrust(derBytes []byte) (*RootOfTrust, error) {
	rot := &RootOfTrust{}

	input := cryptobyte.String(derBytes)
	// we read the SEQUENCE including length and tag bytes so that
	// we can populate RootOfTrust.Raw, before unwrapping the
	// SEQUENCE so it can be operated on
	if !input.ReadASN1Element(&input, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("attestation: malformed RootOfTrust")
	}
	rot.Raw = input
	if !input.ReadASN1(&input, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("attestation: malformed RootOfTrust")
	}

	var vbk cryptobyte.String
	if !input.ReadASN1(&vbk, cryptobyte_asn1.OCTET_STRING) {
		return rot, errors.New("attestation: malformed VerifiedBootKey field")
	}
	rot.VerifiedBootKey = vbk

	if !readASN1Boolean(&input, &rot.DeviceLocked) {
		return rot, errors.New("attestation: malformed DeviceLocked field")
	}

	var vbs int
	if !input.ReadASN1Enum(&vbs) {
		return rot, errors.New("attestation: malformed VerifiedBootState field")
	}
	rot.VerifiedBootState = VerifiedBootState(vbs)

	var vbh cryptobyte.String
	var present bool
	if input.ReadOptionalASN1(&vbh, &present, cryptobyte_asn1.OCTET_STRING) {
		rot.VerifiedBootHash = vbh
	}

	return rot, nil
}

func marshalRoT(rot *RootOfTrust) (derBytes []byte, err error) {
	rootOfTrust := rootOfTrust{
		VerifiedBootKey:   rot.VerifiedBootKey,
		DeviceLocked:      rot.DeviceLocked,
		VerifiedBootState: asn1.Enumerated(rot.VerifiedBootState),
		VerifiedBootHash:  rot.VerifiedBootHash,
	}

	derBytes, err = asn1.Marshal(rootOfTrust)
	if err != nil {
		return nil, fmt.Errorf("attestation: %v", err)
	}

	return derBytes, nil
}

func readASN1Boolean(s *cryptobyte.String, out *bool) bool {
	var bytes cryptobyte.String
	if !s.ReadASN1(&bytes, cryptobyte_asn1.BOOLEAN) || len(bytes) != 1 {
		return false
	}

	switch bytes[0] {
	case 0:
		*out = false
	case 0x01, 0xff:
		*out = true
	default:
		return false
	}

	return true
}

func parseAttestationApplicationId(derBytes []byte) (*attestationApplicationId, error) {
	var attestAppId attestationApplicationId
	if rest, err := asn1.Unmarshal(derBytes, &attestAppId); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("attestation: trailing data after AttestationApplicationId")
	}
	return &attestAppId, nil
}

func marshalAttestationApplicationId(attestaAppId *AttestationApplicationId) (derBytes []byte, err error) {
	appId := attestationApplicationId{
		SignatureDigests: attestaAppId.SignatureDigests,
	}

	for _, p := range attestaAppId.PackageInfos {
		pkg := attestationPackageInfo{
			PackageName: []byte(p.PackageName),
			Version:     p.Version,
		}
		appId.PackageInfos = append(appId.PackageInfos, pkg)
	}

	derBytes, err = asn1.Marshal(appId)
	if err != nil {
		return nil, fmt.Errorf("attestation: %v", err)
	}

	return derBytes, nil
}

func isNullType(v asn1.RawValue) bool {
	return bytes.Equal(v.Bytes, asn1.NullBytes)
}

// GetKeyExtension returns the Key Attestation Extension.
func GetKeyExtension(crt *x509.Certificate) *pkix.Extension {
	for _, ext := range crt.Extensions {
		if ext.Id.Equal(OIDKeyAttestationExtension) {
			return &ext
		}
	}
	return nil
}
