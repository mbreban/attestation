package attestation

type Algorithm uint

func (a Algorithm) String() string {
	switch a {
	case AlgoRSA:
		return "RSA"
	case AlgoEC:
		return "EC"
	case AlgoAES:
		return "AES"
	case AlgoHMAC:
		return "HMAC"
	default:
		return "unknown algorithm"
	}
}

const (
	AlgoRSA  Algorithm = 1
	AlgoEC   Algorithm = 3
	AlgoAES  Algorithm = 32
	AlgoHMAC Algorithm = 128
)

// KeyBlobUsageRequirements specifies the necessary system environment conditions for the generated key to be used.
type KeyBlobUsageRequirements uint

func (r KeyBlobUsageRequirements) String() string {
	return [...]string{
		"STANDALONE",
		"REQUIRES_FILE_SYSTEM",
	}[r]
}

const (
	KBURequirementsStandalone KeyBlobUsageRequirements = iota
	KBURequirementsRequiresFileSystem
)

// BlockMode specifies the block cipher mode(s) with which the key may be used. This tag is only relevant to AES keys.
type BlockMode uint

func (m BlockMode) String() string {
	return [...]string{
		"ECB",
		"CBC",
		"CTR",
		"GCM",
	}[m]
}

const (
	BlockModeECB BlockMode = iota
	BlockModeCBC
	BlockModeCTR
	BlockModeGCM BlockMode = 32
)

// Digest specifies the digest algorithms that may be used with the key to perform signing and verification operations. This tag is relevant to RSA, ECDSA and HMAC keys.
type Digest uint

func (d Digest) String() string {
	return [...]string{
		"NONE",
		"MD5",
		"SHA1",
		"SHA_2_224",
		"SHA_2_256",
		"SHA_2_384",
		"SHA_2_512",
	}[d]
}

const (
	DigestNONE Digest = iota
	DigestMD5
	DigestSHA1
	DigestSHA_2_224
	DigestSHA_2_256
	DigestSHA_2_384
	DigestSHA_2_512
)

// EcCurve specifies the EC curves.
type EcCurve uint

func (c EcCurve) String() string {
	return [...]string{
		"P_224",
		"P_256",
		"P_384",
		"P_521",
	}[c]
}

const (
	CurveP224 EcCurve = iota
	CurveP256
	CurveP384
	CurveP521
)

// KeyOrigin specifies where the key was created, if known.
type KeyOrigin uint

func (o KeyOrigin) String() string {
	return [...]string{
		"GENERATED",
		"DERIVED",
		"IMPORTED",
		"UNKNOWN",
	}[o]
}

const (
	KeyOriginGenerated KeyOrigin = iota
	KeyOriginDerived
	KeyOriginImported
	KeyOriginUnknown
)

// PaddingMode specifies the padding modes that may be used with the key.
type PaddingMode uint

func (m PaddingMode) String() string {
	return [...]string{
		"NONE",
		"RSA_OAEP",
		"RSA_PSS",
		"RSA_PKCS1_1_5_ENCRYPT",
		"RSA_PKCS1_1_5_SIGN",
		"PKCS7",
	}[m]
}

const (
	_                       = iota
	PaddingNone PaddingMode = iota
	PaddingRSA_OAEP
	PaddingRSA_PSS
	PaddingRSA_PKCS1_1_5_ENCRYPT
	PaddingRSA_PKCS1_1_5_SIGN
	PaddingPKCS7 PaddingMode = 64
)

// KeyPurpose specifies the set of purposes for which the key may be used.
type KeyPurpose uint

func (p KeyPurpose) String() string {
	return [...]string{
		"ENCRYPT",
		"DECRYPT",
		"SIGN",
		"VERIFY",
		"DERIVE_KEY",
		"WRAP_KEY",
	}[p]
}

const (
	PurposeEncrypt KeyPurpose = iota
	PurposeDecrypt
	PurposeSign
	PurposeVerify
	PurposeDeriveKey
	PurposeWrapKey
)

// HardwareAuthenticatorType specifies the types of user authenticators that may be used to authorize this key.
type HardwareAuthenticatorType uint

func (t HardwareAuthenticatorType) String() string {
	return [...]string{
		"NONE",
		"PASSWORD",
		"FINGERPRINT",
		"ANY",
	}[t]
}

const (
	HwAuthTypeNone     HardwareAuthenticatorType = iota
	HwAuthTypePassword HardwareAuthenticatorType = 1 << iota
	HwAuthTypeFingerprint
	HwAuthTypeAny HardwareAuthenticatorType = HardwareAuthenticatorType(^uint32(0))
)
