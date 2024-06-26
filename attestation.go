package attestation

import (
	"encoding/asn1"
)

// OIDKeyAttestationExtension is the key attestation extension.
var OIDKeyAttestationExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// keyDescription reflects the ASN.1 data structure for KeyDescription.
//
//	keyDescription ::= SEQUENCE {
//		attestationVersion         INTEGER, # KM2 value is 1. KM3 value is 2. KM4 value is 3.
//		attestationSecurityLevel   SecurityLevel,
//		keymasterVersion           INTEGER,
//		keymasterSecurityLevel     SecurityLevel,
//		attestationChallenge       OCTET_STRING,
//		uniqueId                   OCTET_STRING,
//		softwareEnforced           AuthorizationList,
//		teeEnforced                AuthorizationList,
//	}
type keyDescription struct {
	Raw                      asn1.RawContent
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueId                 []byte
	SoftwareEnforced         asn1.RawValue
	TeeEnforced              asn1.RawValue
}

// KeyDescription reflects the attestation extension content.
//
// This sequence of values presents general information about the key pair being verified through
// key attestation and provides easy access to additional details.
type KeyDescription struct {
	Raw                      []byte
	AttestationVersion       AttestationVersion
	AttestationSecurityLevel SecurityLevel
	KeymasterVersion         KeymasterVersion
	KeymasterSecurityLevel   SecurityLevel
	AttestationChallenge     []byte
	UniqueId                 []byte
	SoftwareEnforced         AuthorizationList
	TeeEnforced              AuthorizationList
}

// AttestationVersion is the version of attestation schema.
type AttestationVersion uint

// String returns the string representation.
func (v AttestationVersion) String() string {
	switch v {
	case KAKeymasterVersion2:
		return "Keymaster version 2.0"
	case KAKeymasterVersion3:
		return "Keymaster version 3.0"
	case KAKeymasterVersion4:
		return "Keymaster version 4.0"
	case KAKeymasterVersion41:
		return "Keymaster version 4.1"
	case KAKeyMintVersion1:
		return "KeyMint version 1.0"
	case KAKeyMintVersion2:
		return "KeyMint version 2.0"
	case KAKeyMintVersion3:
		return "KeyMint version 3.0"
	default:
		return ""
	}
}

const (
	KAKeymasterVersion2  AttestationVersion = iota + 1 // Keymaster version 2.0
	KAKeymasterVersion3                                // Keymaster version 3.0
	KAKeymasterVersion4                                // Keymaster version 4.0
	KAKeymasterVersion41                               // Keymaster version 4.1
	KAKeyMintVersion1    = 100                         // KeyMint version 1.0
	KAKeyMintVersion2    = 200                         // KeyMint version 2.0
	KAKeyMintVersion3    = 300                         // KeyMint version 3.0
)

// KeymasterVersion is the version of the Keymaster or KeyMint hardware abstraction layer.
type KeymasterVersion uint

// String returns the string representation.
func (v KeymasterVersion) String() string {
	switch v {
	case KeymasterVersion0:
		return "Keymaster version 0"
	case KeymasterVersion1:
		return "Keymaster version 1"
	case KeymasterVersion2:
		return "Keymaster version 2"
	case KeymasterVersion3:
		return "Keymaster version 3"
	case KeymasterVersion4:
		return "Keymaster version 4"
	case KeymasterVersion41:
		return "Keymaster version 4.1"
	case KeyMintVersion1:
		return "KeyMint version 1.0"
	case KeyMintVersion2:
		return "KeyMint version 2.0"
	case KeyMintVersion3:
		return "KeyMint version 3.0"
	default:
		return ""
	}
}

const (
	KeymasterVersion0  KeymasterVersion = iota // Keymaster version 0.2 or 0.3
	KeymasterVersion1                          // Keymaster version 1.0
	KeymasterVersion2                          // Keymaster version 2.0
	KeymasterVersion3                          // Keymaster version 3.0
	KeymasterVersion4                          // Keymaster version 4.0
	KeymasterVersion41 = 41                    // Keymaster version 4.1
	KeyMintVersion1    = 100                   // KeyMint version 1.0
	KeyMintVersion2    = 200                   // KeyMint version 2.0
	KeyMintVersion3    = 300                   // KeyMint version 3.0
)

// SecurityLevel reflects the ASN.1 data structure for SecurityLevel.
//
// This data structure indicates the extent to which a software feature, such as a key pair, is
// protected based on its location within the device.
//
//	SecurityLevel ::= ENUMERATED {
//	    Software                   (0),
//	    TrustedEnvironment         (1),
//	    StrongBox                  (2),
//	}
type SecurityLevel uint

// String returns the string representation.
func (l SecurityLevel) String() string {
	return [...]string{
		"Software",
		"TrustedEnvironment",
		"StrongBox",
	}[l]
}

// The security level of the attestation.
const (
	Software SecurityLevel = iota
	TrustedEnvironment
	StrongBox
)

// authorizationList reflects the ASN.1 data structure for AuthorizationList.
//
//	AuthorizationList ::= SEQUENCE {
//		purpose                     [1] EXPLICIT SET OF INTEGER OPTIONAL,
//		algorithm                   [2] EXPLICIT INTEGER OPTIONAL,
//		keySize                     [3] EXPLICIT INTEGER OPTIONAL.
//		digest                      [5] EXPLICIT SET OF INTEGER OPTIONAL,
//		padding                     [6] EXPLICIT SET OF INTEGER OPTIONAL,
//		ecCurve                     [10] EXPLICIT INTEGER OPTIONAL,
//		rsaPublicExponent           [200] EXPLICIT INTEGER OPTIONAL,
//		rollbackResistance          [303] EXPLICIT NULL OPTIONAL, # KM4
//		activeDateTime              [400] EXPLICIT INTEGER OPTIONAL
//		originationExpireDateTime   [401] EXPLICIT INTEGER OPTIONAL
//		usageExpireDateTime         [402] EXPLICIT INTEGER OPTIONAL
//		noAuthRequired              [503] EXPLICIT NULL OPTIONAL,
//		userAuthType                [504] EXPLICIT INTEGER OPTIONAL,
//		authTimeout                 [505] EXPLICIT INTEGER OPTIONAL,
//		allowWhileOnBody            [506] EXPLICIT NULL OPTIONAL,
//		trustedUserPresenceRequired [507] EXPLICIT NULL OPTIONAL, # KM4
//		trustedConfirmationRequired [508] EXPLICIT NULL OPTIONAL, # KM4
//		unlockedDeviceRequired      [509] EXPLICIT NULL OPTIONAL, # KM4
//		allApplications             [600] EXPLICIT NULL OPTIONAL,
//		applicationId               [601] EXPLICIT OCTET_STRING OPTIONAL,
//		creationDateTime            [701] EXPLICIT INTEGER OPTIONAL,
//		origin                      [702] EXPLICIT INTEGER OPTIONAL,
//		rollbackResistant           [703] EXPLICIT NULL OPTIONAL, # KM2 and KM3 only.
//		rootOfTrust                 [704] EXPLICIT RootOfTrust OPTIONAL,
//		osVersion                   [705] EXPLICIT INTEGER OPTIONAL,
//		osPatchLevel                [706] EXPLICIT INTEGER OPTIONAL,
//		attestationApplicationId    [709] EXPLICIT OCTET_STRING OPTIONAL, # KM3
//		attestationIdBrand          [710] EXPLICIT OCTET_STRING OPTIONAL, # KM3
//		attestationIdDevice         [711] EXPLICIT OCTET_STRING OPTIONAL, # KM3
//		attestationIdProduct        [712] EXPLICIT OCTET_STRING OPTIONAL, # KM3
//		attestationIdSerial         [713] EXPLICIT OCTET_STRING OPTIONAL, # KM3
//		attestationIdImei           [714] EXPLICIT OCTET_STRING OPTIONAL, # KM3
//		attestationIdMeid           [715] EXPLICIT OCTET_STRING OPTIONAL, # KM3
//		attestationIdManufacturer   [716] EXPLICIT OCTET_STRING OPTIONAL, # KM3
//		attestationIdModel          [717] EXPLICIT OCTET_STRING OPTIONAL, # KM3
//		vendorPatchLevel            [718] EXPLICIT INTEGER OPTIONAL, # KM4
//		bootPatchLevel              [719] EXPLICIT INTEGER OPTIONAL, # KM4
//	}
type authorizationList struct {
	Raw                         asn1.RawContent
	Purpose                     []int32         `asn1:"explicit,optional,omitempty,set,tag:1"` // [1] EXPLICIT SET OF INTEGER OPTIONAL,
	Algorithm                   asn1.RawValue   `asn1:"explicit,optional,tag:2"`               // [2] EXPLICIT INTEGER OPTIONAL,
	KeySize                     asn1.RawValue   `asn1:"explicit,optional,tag:3"`               // [3] EXPLICIT INTEGER OPTIONAL.
	Digest                      []int           `asn1:"explicit,optional,omitempty,set,tag:5"` // [5] EXPLICIT SET OF INTEGER OPTIONAL,
	Padding                     []int           `asn1:"explicit,optional,omitempty,set,tag:6"` // [6] EXPLICIT SET OF INTEGER OPTIONAL,
	EcCurve                     asn1.RawValue   `asn1:"explicit,optional,tag:10"`              // [10] EXPLICIT INTEGER OPTIONAL,
	RsaPublicExponent           asn1.RawValue   `asn1:"explicit,optional,tag:200"`             // [200] EXPLICIT INTEGER OPTIONAL,
	RollbackResistance          asn1.RawValue   `asn1:"explicit,optional,tag:303"`             // [303] EXPLICIT NULL OPTIONAL, # KM4
	ActiveDateTime              asn1.RawValue   `asn1:"explicit,optional,tag:400"`             // [400] EXPLICIT INTEGER OPTIONAL
	OriginationExpireDateTime   asn1.RawValue   `asn1:"explicit,optional,tag:401"`             // [401] EXPLICIT INTEGER OPTIONAL
	UsageExpireDateTime         asn1.RawValue   `asn1:"explicit,optional,tag:402"`             // [402] EXPLICIT INTEGER OPTIONAL
	NoAuthRequired              asn1.RawValue   `asn1:"explicit,optional,tag:503"`             // [503] EXPLICIT NULL OPTIONAL,
	UserAuthType                asn1.RawValue   `asn1:"explicit,optional,tag:504"`             // [504] EXPLICIT INTEGER OPTIONAL,
	AuthTimeout                 asn1.RawValue   `asn1:"explicit,optional,tag:505"`             // [505] EXPLICIT INTEGER OPTIONAL,
	AllowWhileOnBody            asn1.RawValue   `asn1:"explicit,optional,tag:506"`             // [506] EXPLICIT NULL OPTIONAL,
	TrustedUserPresenceRequired asn1.RawValue   `asn1:"explicit,optional,tag:507"`             // [507] EXPLICIT NULL OPTIONAL, # KM4
	TrustedConfirmationRequired asn1.RawValue   `asn1:"explicit,optional,tag:508"`             // [508] EXPLICIT NULL OPTIONAL, # KM4
	UnlockedDeviceRequired      asn1.RawValue   `asn1:"explicit,optional,tag:509"`             // [509] EXPLICIT NULL OPTIONAL, # KM4
	AllApplications             asn1.RawValue   `asn1:"explicit,optional,tag:600"`             // [600] EXPLICIT NULL OPTIONAL,
	ApplicationId               []byte          `asn1:"explicit,optional,omitempty,tag:601"`   // [601] EXPLICIT OCTET_STRING OPTIONAL,
	CreationDateTime            asn1.RawValue   `asn1:"explicit,optional,tag:701"`             // [701] EXPLICIT INTEGER OPTIONAL,
	Origin                      asn1.RawValue   `asn1:"explicit,optional,tag:702"`             // [702] EXPLICIT INTEGER OPTIONAL,
	RollbackResistant           asn1.RawValue   `asn1:"explicit,optional,tag:703"`             // [703] EXPLICIT NULL OPTIONAL, # KM2 and KM3 only.
	RootOfTrust                 asn1.RawValue   `asn1:"explicit,optional,tag:704"`             // [704] EXPLICIT RootOfTrust OPTIONAL,
	OsVersion                   asn1.RawValue   `asn1:"explicit,optional,tag:705"`             // [705] EXPLICIT INTEGER OPTIONAL,
	OsPatchLevel                asn1.RawValue   `asn1:"explicit,optional,tag:706"`             // [706] EXPLICIT INTEGER OPTIONAL,
	AttestationApplicationId    asn1.RawContent `asn1:"explicit,optional,tag:709"`             // [709] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	AttestationIdBrand          []byte          `asn1:"explicit,optional,omitempty,tag:710"`   // [710] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	AttestationIdDevice         []byte          `asn1:"explicit,optional,omitempty,tag:711"`   // [711] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	AttestationIdProduct        []byte          `asn1:"explicit,optional,omitempty,tag:712"`   // [712] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	AttestationIdSerial         []byte          `asn1:"explicit,optional,omitempty,tag:713"`   // [713] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	AttestationIdImei           []byte          `asn1:"explicit,optional,omitempty,tag:714"`   // [714] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	AttestationIdMeid           []byte          `asn1:"explicit,optional,omitempty,tag:715"`   // [715] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	AttestationIdManufacturer   []byte          `asn1:"explicit,optional,omitempty,tag:716"`   // [716] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	AttestationIdModel          []byte          `asn1:"explicit,optional,omitempty,tag:717"`   // [717] EXPLICIT OCTET_STRING OPTIONAL, # KM3
	VendorPatchLevel            asn1.RawValue   `asn1:"explicit,optional,tag:718"`             // [718] EXPLICIT INTEGER OPTIONAL, # KM4
	BootPatchLevel              asn1.RawValue   `asn1:"explicit,optional,tag:719"`             // [719] EXPLICIT INTEGER OPTIONAL, # KM4
}

// AuthorizationList reflects the key pair's properties as defined in the Keymaster or KeyMint
// hardware abstraction layer.
type AuthorizationList struct {
	Raw                         []byte
	Purpose                     []KeyPurpose
	Algorithm                   *Algorithm
	KeySize                     *int
	Digest                      []Digest
	Padding                     []PaddingMode
	EcCurve                     *EcCurve
	RsaPublicExponent           *int64
	RollbackResistance          bool
	ActiveDateTime              *int64
	OriginationExpireDateTime   *int
	UsageExpireDateTime         *int64
	NoAuthRequired              bool
	UserAuthType                *HardwareAuthenticatorType
	AuthTimeout                 *int32
	AllowWhileOnBody            bool
	TrustedUserPresenceRequired bool
	TrustedConfirmationRequired bool
	UnlockedDeviceRequired      bool
	AllApplications             bool
	ApplicationId               []byte
	CreationDateTime            *int
	Origin                      *KeyOrigin
	RollbackResistant           bool
	RootOfTrust                 *RootOfTrust
	OsVersion                   *int
	OsPatchLevel                *int
	AttestationApplicationId    *AttestationApplicationId
	AttestationIdBrand          []byte
	AttestationIdDevice         []byte
	AttestationIdProduct        []byte
	AttestationIdSerial         []byte
	AttestationIdImei           []byte
	AttestationIdMeid           []byte
	AttestationIdManufacturer   []byte
	AttestationIdModel          []byte
	VendorPatchLevel            *int
	BootPatchLevel              *int
}

// RootOfTrust reflects the ASN.1 data structure for RootOfTrust.
//
//	RootOfTrust ::= SEQUENCE {
//		verifiedBootKey            OCTET_STRING,
//		deviceLocked               BOOLEAN,
//		verifiedBootState          VerifiedBootState,
//		verifiedBootHash           OCTET_STRING, # KM4
//	}
type rootOfTrust struct {
	Raw               asn1.RawContent
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional,omitempty"`
}

// RootOfTrust reflects information on Android secure boot.
type RootOfTrust struct {
	Raw               []byte
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState VerifiedBootState
	VerifiedBootHash  []byte
}

// VerifiedBootState reflects the ASN.1 data structure for VerifiedBootState.
//
//	VerifiedBootState ::= ENUMERATED {
//		Verified                   (0),
//		SelfSigned                 (1),
//		Unverified                 (2),
//		Failed                     (3),
//	}
type VerifiedBootState uint

// String returns the string representation.
func (s VerifiedBootState) String() string {
	return [...]string{
		"Verified",
		"SelfSigned",
		"Unverified",
		"Failed",
	}[s]
}

// VerifiedBootState is the state of verified boot.
const (
	Verified   = iota // Indicates a full chain of trust, which includes the bootloader, the boot partition, and all verified partitions.
	SelfSigned        // Indicates that the device-embedded certificate has verified the device's boot partition and that the signature is valid.
	Unverified        // Indicates that the user can modify the device freely. Therefore, the user is responsible for verifying the device's integrity.
	Failed            // Indicates that the device has failed verification. The attestation certificate should never use this value for VerifiedBootState.
)

// attestationApplicationId reflects the ASN.1 data structure for AttestationApplicationId.
//
//	AttestationApplicationId ::= SEQUENCE {
//	    package_infos  SET OF AttestationPackageInfo,
//	    signature_digests  SET OF OCTET_STRING,
//	}
type attestationApplicationId struct {
	Raw              asn1.RawContent
	PackageInfos     []attestationPackageInfo `asn1:"set"`
	SignatureDigests [][]byte                 `asn1:"set"`
}

// attestationPackageInfo reflects the ASN.1 data structure for AttestationPackageInfo.
//
//	AttestationPackageInfo ::= SEQUENCE {
//	    package_name  OCTET_STRING,
//	    version  INTEGER,
//	}
type attestationPackageInfo struct {
	PackageName []byte
	Version     int
}

// AttestationApplicationId reflects the Android platform's belief as to which apps are allowed to
// use the secret key material under attestation. The ID can comprise multiple packages if and only
// if multiple packages share the same UID.
type AttestationApplicationId struct {
	PackageInfos     []*AttestationPackageInfo
	SignatureDigests [][]byte
}

// AttestationPackageInfo reflects a package's name and version number.
type AttestationPackageInfo struct {
	PackageName string
	Version     int
}
