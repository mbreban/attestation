package attestation

// AuthorizationList

const (
	TagPurpose                     = 1   // Corresponds to the Tag::PURPOSE authorization tag, which uses a tag ID value of 1.
	TagAlgorithm                   = 2   // Corresponds to the Tag::ALGORITHM authorization tag, which uses a tag ID value of 2. // In an attestation AuthorizationList object, the algorithm value is always RSA or EC.
	TagKeySize                     = 3   // Corresponds to the Tag::KEY_SIZE authorization tag, which uses a tag ID value of 3.
	TagDigest                      = 5   // Corresponds to the Tag::DIGEST authorization tag, which uses a tag ID value of 5.
	TagPadding                     = 6   // Corresponds to the Tag::PADDING authorization tag, which uses a tag ID value of 6.
	TagEcCurve                     = 10  // Corresponds to the Tag::EC_CURVE authorization tag, which uses a tag ID value of 10. // The set of parameters used to generate an elliptic curve (EC) key pair, which uses ECDSA for signing and verification, within the Android system keystore.
	TagRsaPublicExponent           = 200 // Corresponds to the Tag::RSA_PUBLIC_EXPONENT authorization tag, which uses a tag ID value of 200.
	TagMgfDigest                   = 203 // Present only in key attestation version >= 100. // Corresponds to the Tag::RSA_OAEP_MGF_DIGEST KeyMint authorization tag, which uses a tag ID value of 203.
	TagRollbackResistance          = 303 // Present only in key attestation version >= 3. // Corresponds to the Tag::ROLLBACK_RESISTANT authorization tag, which uses a tag ID value of 303.
	TagEarlyBootOnly               = 305 // Present only in key attestation version >= 4. // Corresponds to the Tag::EARLY_BOOT_ONLY authorization tag, which uses a tag ID value of 305.
	TagActiveDateTime              = 400 // Corresponds to the Tag::ACTIVE_DATETIME authorization tag, which uses a tag ID value of 400.
	TagOriginationExpireDateTime   = 401 // Corresponds to the Tag::ORIGINATION_EXPIRE_DATETIME Keymaster authorization tag, which uses a tag ID value of 401.
	TagUsageExpireDateTime         = 402 // Corresponds to the Tag::USAGE_EXPIRE_DATETIME authorization tag, which uses a tag ID value of 402.
	TagUsageCountLimit             = 405 // Corresponds to the Tag::USAGE_COUNT_LIMIT authorization tag, which uses a tag ID value of 405.
	TagNoAuthRequired              = 503 // Corresponds to the Tag::NO_AUTH_REQUIRED authorization tag, which uses a tag ID value of 503.
	TagUserAuthType                = 504 // Corresponds to the Tag::USER_AUTH_TYPE authorization tag, which uses a tag ID value of 504.
	TagAuthTimeout                 = 505 // Corresponds to the Tag::AUTH_TIMEOUT authorization tag, which uses a tag ID value of 505.
	TagAllowWhileOnBody            = 506 // Corresponds to the Tag::ALLOW_WHILE_ON_BODY authorization tag, which uses a tag ID value of 506. // Allows the key to be used after its authentication timeout period if the user is still wearing the device on their body. Note that a secure on-body sensor determines whether the device is being worn on the user's body.
	TagTrustedUserPresenceRequired = 507 // Present only in key attestation version >= 3. // Corresponds to the Tag::TRUSTED_USER_PRESENCE_REQUIRED authorization tag, which uses a tag ID value of 507. // Specifies that this key is usable only if the user has provided proof of physical presence. Several examples include the following: //     For a StrongBox key, a hardware button hardwired to a pin on the StrongBox device. //     For a TEE key, fingerprint authentication provides proof of presence as long as the TEE has exclusive control of the scanner and performs the fingerprint matching process.
	TagTrustedConfirmationRequired = 508 // Present only in key attestation version >= 3. // Corresponds to the Tag::TRUSTED_CONFIRMATION_REQUIRED authorization tag, which uses a tag ID value of 508. // Specifies that the key is usable only if the user provides confirmation of the data to be signed using an approval token. For more information about how to obtain user confirmation, see Android Protected Confirmation. // Note: This tag is only applicable to keys that use the SIGN purpose.
	TagUnlockedDeviceRequired      = 509 // Present only in key attestation version >= 3. // Corresponds to the Tag::UNLOCKED_DEVICE_REQUIRED authorization tag, which uses a tag ID value of 509.
	TagAllApplications             = 600 // Corresponds to the Tag::ALL_APPLICATIONS authorization tag, which uses a tag ID value of 600. // Indicates whether all apps on a device can access the key pair.
	TagApplicationId               = 601 // Corresponds to the Tag::APPLICATION_ID authorization tag, which uses a tag ID value of 601.
	TagCreationDateTime            = 701 // Corresponds to the Tag::CREATION_DATETIME authorization tag, which uses a tag ID value of 701.
	TagOrigin                      = 702 // Corresponds to the Tag::ORIGIN authorization tag, which uses a tag ID value of 702.
	TagRollbackResistant           = 703 // Present only in key attestation versions 1 and 2. // Corresponds to the Tag::ROLLBACK_RESISTANT authorization tag, which uses a tag ID value of 703.
	TagRootOfTrust                 = 704 // Corresponds to the Tag::ROOT_OF_TRUST authorization tag, which uses a tag ID value of 704. // For more details, see the section describing the RootOfTrust data structure.
	TagOsVersion                   = 705 // Corresponds to the Tag::OS_VERSION authorization tag, which uses a tag ID value of 705. // The version of the Android operating system associated with the Keymaster, specified as a six-digit integer. For example, version 8.1.0 is represented as 080100. // Only Keymaster version 1.0 or higher includes this value in the authorization list.
	TagOsPatchLevel                = 706 // Corresponds to the Tag::PATCHLEVEL authorization tag, which uses a tag ID value of 706. // The month and year associated with the security patch that is being used within the Keymaster, specified as a six-digit integer. For example, the August 2018 patch is represented as 201808. // Only Keymaster version 1.0 or higher includes this value in the authorization list.
	TagAttestationApplicationId    = 709 // Present only in key attestation versions >= 2. // Corresponds to the Tag::ATTESTATION_APPLICATION_ID Keymaster authorization tag, which uses a tag ID value of 709. // For more details, see the section describing the AttestationApplicationId data structure.
	TagAttestationIdBrand          = 710 // Present only in key attestation versions >= 2. // Corresponds to the Tag::ATTESTATION_ID_BRAND Keymaster tag, which uses a tag ID value of 710.
	TagAttestationIdDevice         = 711 // Present only in key attestation versions >= 2. // Corresponds to the Tag::ATTESTATION_ID_DEVICE Keymaster tag, which uses a tag ID value of 711.
	TagAttestationIdProduct        = 712 // Present only in key attestation versions >= 2. // Corresponds to the Tag::ATTESTATION_ID_PRODUCT Keymaster tag, which uses a tag ID value of 712.
	TagAttestationIdSerial         = 713 // Present only in key attestation versions >= 2. // Corresponds to the Tag::ATTESTATION_ID_SERIAL Keymaster tag, which uses a tag ID value of 713.
	TagAttestationIdImei           = 714 // Present only in key attestation versions >= 2. // Corresponds to the Tag::ATTESTATION_ID_IMEI authorization tag, which uses a tag ID value of 714.
	TagAttestationIdMeid           = 715 // Present only in key attestation versions >= 2. // Corresponds to the Tag::ATTESTATION_ID_MEID authorization tag, which uses a tag ID value of 715.
	TagAttestationIdManufacturer   = 716 // Present only in key attestation versions >= 2. // Corresponds to the Tag::ATTESTATION_ID_MANUFACTURER authorization tag, which uses a tag ID value of 716.
	TagAttestationIdModel          = 717 // Present only in key attestation versions >= 2. // Corresponds to the Tag::ATTESTATION_ID_MODEL authorization tag, which uses a tag ID value of 717.
	TagVendorPatchLevel            = 718 // Present only in key attestation versions >= 3. // Corresponds to the Tag::VENDOR_PATCHLEVEL authorization tag, which uses a tag ID value of 718. // Specifies the vendor image security patch level that must be installed on the device for this key to be used. The value appears in the form YYYYMMDD, representing the date of the vendor security patch. For example, if a key were generated on an Android device with the vendor's August 1, 2018 security patch installed, this value would be 20180801.
	TagBootPatchLevel              = 719 // Present only in key attestation versions >= 3. // Corresponds to the Tag::BOOT_PATCHLEVEL authorization tag, which uses a tag ID value of 719. // Specifies the kernel image security patch level that must be installed on the device for this key to be used. The value appears in the form YYYYMMDD, representing the date of the system security patch. For example, if a key were generated on an Android device with the system's August 5, 2018 security patch installed, this value would be 20180805.
	TagDeviceUniqueAttestation     = 720 // Present only in key attestation versions >= 4. // Corresponds to the Tag::DEVICE_UNIQUE_ATTESTATION authorization tag, which uses a tag ID value of 720.
)

// RootOfTrust

const (
	TagVerifiedBootKey   = iota // A secure hash of the key that verifies the system image. It is recommended that you use the SHA-256 algorithm for this hash.
	TagDeviceLocked             // True if the device's bootloader is locked, which enables Verified Boot checking and prevents an unsigned device image from being flashed onto the device. For more information about this feature, see the Verifying Boot documentation.
	TagVerifiedBootState        // The boot state of the device, according to the Verified Boot feature.
	TagVerifiedBootHash         // A digest of all data protected by Verified Boot.
)
