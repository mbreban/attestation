package attestation

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func Test_createAuthorizationList(t *testing.T) {
	type args struct {
		authList *AuthorizationList
	}
	tests := []struct {
		name    string
		args    args
		want    *authorizationList
		wantErr bool
	}{
		{
			name:    "shouldFailWhenNil",
			args:    args{},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "shouldSucceedWhenEmpty",
			args:    args{authList: &AuthorizationList{}},
			want:    &authorizationList{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createAuthorizationList(tt.args.authList)
			if (err != nil) != tt.wantErr {
				t.Errorf("createAuthorizationList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createAuthorizationList() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCreateKeyDescription(t *testing.T) {
	type args struct {
		template *KeyDescription
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "shouldFailWhenNil",
			args:    args{},
			want:    nil,
			wantErr: true,
		},
		{
			name: "shouldSucceedWhenEmpty",
			args: args{template: &KeyDescription{}},
			want: []byte{
				0x30,                        // SEQUENCE
				0x14,                        // LENGTH
				asn1.TagInteger, 0x01, 0x00, // AttestationVersion
				asn1.TagEnum, 0x01, 0x00, // AttestationSecurityLevel
				asn1.TagInteger, 0x01, 0x00, // KeymasterVersion
				asn1.TagEnum, 0x01, 0x00, // KeymasterSecurityLevel
				asn1.TagOctetString, 0x00, // AttestationChallenge
				asn1.TagOctetString, 0x00, // UniqueId
				0x30, 0x00, // SoftwareEnforced
				0x30, 0x00, // TeeEnforced
			},
			wantErr: false,
		},
		{
			name: "shouldSucceedWithValues",
			args: args{template: &KeyDescription{
				AttestationVersion:       KAKeymasterVersion41,
				AttestationSecurityLevel: StrongBox,
				KeymasterVersion:         KeymasterVersion41,
				KeymasterSecurityLevel:   StrongBox,
				AttestationChallenge:     []byte("test"),
				UniqueId:                 []byte("test"),
			}},
			want: []byte{
				0x30,                                              // SEQUENCE
				0x1c,                                              // LENGTH
				asn1.TagInteger, 0x01, byte(KAKeymasterVersion41), // AttestationVersion
				asn1.TagEnum, 0x01, byte(StrongBox), // AttestationSecurityLevel
				asn1.TagInteger, 0x01, byte(KeymasterVersion41), // KeymasterVersion
				asn1.TagEnum, 0x01, byte(StrongBox), // KeymasterSecurityLevel
				asn1.TagOctetString, 0x04, 't', 'e', 's', 't', // AttestationChallenge
				asn1.TagOctetString, 0x04, 't', 'e', 's', 't', // UniqueId
				0x30, 0x00, // SoftwareEnforced
				0x30, 0x00, // TeeEnforced
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateKeyDescription(tt.args.template)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateKeyDescription() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateKeyDescription() = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestCreateExtension(t *testing.T) {
	type args struct {
		template *KeyDescription
	}
	tests := []struct {
		name    string
		args    args
		want    *pkix.Extension
		wantErr bool
	}{
		{
			name:    "shouldFailWhenNil",
			args:    args{},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateExtension(tt.args.template)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateExtension() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateExtension() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseExtension(t *testing.T) {
	raw := []byte{
		0x30,                                              // SEQUENCE
		0x1c,                                              // LENGTH
		asn1.TagInteger, 0x01, byte(KAKeymasterVersion41), // AttestationVersion
		asn1.TagEnum, 0x01, byte(StrongBox), // AttestationSecurityLevel
		asn1.TagInteger, 0x01, byte(KeymasterVersion41), // KeymasterVersion
		asn1.TagEnum, 0x01, byte(StrongBox), // KeymasterSecurityLevel
		asn1.TagOctetString, 0x04, 't', 'e', 's', 't', // AttestationChallenge
		asn1.TagOctetString, 0x04, 't', 'e', 's', 't', // UniqueId
		0x30, 0x00, // SoftwareEnforced
		0x30, 0x00, // TeeEnforced
	}

	type args struct {
		derBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *KeyDescription
		wantErr bool
	}{
		{
			name:    "shouldFailWhenNil",
			args:    args{},
			want:    nil,
			wantErr: true,
		},
		{
			name: "shouldSucceedWithValues",
			args: args{derBytes: raw},
			want: &KeyDescription{
				Raw:                      raw,
				AttestationVersion:       KAKeymasterVersion41,
				AttestationSecurityLevel: StrongBox,
				KeymasterVersion:         KeymasterVersion41,
				KeymasterSecurityLevel:   StrongBox,
				AttestationChallenge:     []byte("test"),
				UniqueId:                 []byte("test"),
				SoftwareEnforced:         AuthorizationList{Raw: []byte{0x30, 0x00}},
				TeeEnforced:              AuthorizationList{Raw: []byte{0x30, 0x00}},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseExtension(tt.args.derBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseExtension() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseExtension() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func Test_parseAuthorizationList(t *testing.T) {
	raw := []byte{0x30, 0x00}

	type args struct {
		derBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *authorizationList
		wantErr bool
	}{
		{
			name:    "shouldFaildWhenNil",
			args:    args{},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "shouldFaildWhenEmpty",
			args:    args{derBytes: []byte{}},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "shouldSucceedWhenValidAndEmpty",
			args:    args{derBytes: raw},
			want:    &authorizationList{Raw: raw},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAuthorizationList(tt.args.derBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAuthorizationList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAuthorizationList() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func Test_parseRootOfTrust(t *testing.T) {
	raw1 := []byte{
		0x30,                                          // SEQUENCE
		0x0c,                                          // LENGTH
		asn1.TagOctetString, 0x04, 't', 'e', 's', 't', // VerifiedBootKey
		asn1.TagBoolean, 0x01, 0xff, // DeviceLocked
		asn1.TagEnum, 0x01, byte(Unverified), // VerifiedBootState
	}

	raw2 := []byte{
		0x30,                                          // SEQUENCE
		0x0c,                                          // LENGTH
		asn1.TagOctetString, 0x04, 't', 'e', 's', 't', // VerifiedBootKey
		asn1.TagBoolean, 0x01, 0x01, // DeviceLocked
		asn1.TagEnum, 0x01, byte(Unverified), // VerifiedBootState
	}

	raw3 := []byte{
		0x30,                                          // SEQUENCE
		0x12,                                          // LENGTH
		asn1.TagOctetString, 0x04, 't', 'e', 's', 't', // VerifiedBootKey
		asn1.TagBoolean, 0x01, 0xff, // DeviceLocked
		asn1.TagEnum, 0x01, byte(Unverified), // VerifiedBootState
		asn1.TagOctetString, 0x04, 't', 'e', 's', 't', // VerifiedBootHash
	}

	type args struct {
		derBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *RootOfTrust
		wantErr bool
	}{
		{
			name:    "shouldFailWhenNil",
			args:    args{},
			want:    nil,
			wantErr: true,
		},
		{
			name: "shouldSucceedWithoutVerifiedBootHash",
			args: args{derBytes: raw1},
			want: &RootOfTrust{
				Raw:               raw1,
				VerifiedBootKey:   []byte{'t', 'e', 's', 't'},
				DeviceLocked:      true,
				VerifiedBootState: Unverified,
			},
			wantErr: false,
		},
		{
			name: "shouldSucceedWithNonStandardBool",
			args: args{derBytes: raw2},
			want: &RootOfTrust{
				Raw:               raw2,
				VerifiedBootKey:   []byte{'t', 'e', 's', 't'},
				DeviceLocked:      true,
				VerifiedBootState: Unverified,
			},
			wantErr: false,
		},
		{
			name: "shouldSucceedWithVerifiedBootHash",
			args: args{derBytes: raw3},
			want: &RootOfTrust{
				Raw:               raw3,
				VerifiedBootKey:   []byte{'t', 'e', 's', 't'},
				DeviceLocked:      true,
				VerifiedBootState: Unverified,
				VerifiedBootHash:  []byte{'t', 'e', 's', 't'},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRootOfTrust(tt.args.derBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRootOfTrust() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseRootOfTrust() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func Test_readASN1Boolean(t *testing.T) {
	var input = cryptobyte.String([]byte{
		asn1.TagBoolean, 0x01, 0xaa,
		asn1.TagBoolean, 0x01, 0x00,
		asn1.TagBoolean, 0x01, 0xff,
		asn1.TagBoolean, 0x01, 0x01,
	})
	var outBool bool

	type args struct {
		s   *cryptobyte.String
		out *bool
	}
	type want struct {
		ret bool
		out bool
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "shouldFailWhenInvalid",
			args: args{s: &input, out: &outBool},
			want: want{ret: false, out: false},
		},
		{
			name: "shouldSucceedWith0x00",
			args: args{s: &input, out: &outBool},
			want: want{ret: true, out: false},
		},
		{
			name: "shouldSucceedWith0xFF",
			args: args{s: &input, out: &outBool},
			want: want{ret: true, out: true},
		},
		{
			name: "shouldSucceedWith0x01",
			args: args{s: &input, out: &outBool},
			want: want{ret: true, out: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := readASN1Boolean(tt.args.s, tt.args.out); got != tt.want.ret {
				t.Errorf("readASN1Boolean() = %v, want %v", got, tt.want.ret)
			}
			if *tt.args.out != tt.want.out {
				t.Errorf("readASN1Boolean() = %v, want %v", *tt.args.out, tt.want.out)
			}
		})
	}
}
