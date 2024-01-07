package fido

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var ErrMalformedData = errors.New("data malformed")

// > The authenticator data structure encodes contextual bindings made by the authenticator.
// https://www.w3.org/TR/webauthn-2/#authenticator-data
// UnmarshalBinary can be used to parse data
type AuthenticatorData struct {
	RPIDHash               []byte
	Flags                  AuthenticatorDataFlag
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	Extensions             map[string]any
}

func (d *AuthenticatorData) UnmarshalBinary(data []byte) error {
	if len(data) < 37 {
		return ErrMalformedData
	}
	d.RPIDHash = data[0:32]
	d.Flags = AuthenticatorDataFlag(data[32])
	d.SignCount = binary.BigEndian.Uint32(data[33:37])
	if len(data) > 37 {
		var dec *cbor.Decoder
		if (d.Flags & AuthenticatorDataFlagAttestedCredentialDataIncluded) != 0 {
			if len(data) < 55 {
				return ErrMalformedData
			}
			d.AttestedCredentialData = &AttestedCredentialData{
				AAGUID:             data[37:53],
				CredentialIdLength: binary.BigEndian.Uint16(data[53:55]),
			}
			if len(data) < 55+int(d.AttestedCredentialData.CredentialIdLength) {
				return ErrMalformedData
			}
			d.AttestedCredentialData.CredentialId = data[55 : 55+int(d.AttestedCredentialData.CredentialIdLength)]
			dec = cbor.NewDecoder(bytes.NewReader(data[55+int(d.AttestedCredentialData.CredentialIdLength):]))
			err := dec.Decode(&d.AttestedCredentialData.CredentialPublicKey)
			if err != nil {
				return err
			}
		} else {
			dec = cbor.NewDecoder(bytes.NewReader(data[33:]))
		}
		if (d.Flags & AuthenticatorDataFlagExtentionDataIncluded) != 0 {
			err := dec.Decode(&d.Extensions)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type AuthenticatorDataFlag uint8

const (
	AuthenticatorDataFlagUserPresent                    AuthenticatorDataFlag = 0x01
	AuthenticatorDataFlagUserVerified                   AuthenticatorDataFlag = 0x04
	AuthenticatorDataFlagAttestedCredentialDataIncluded AuthenticatorDataFlag = 0x40
	AuthenticatorDataFlagExtentionDataIncluded          AuthenticatorDataFlag = 0x80
)

type AttestedCredentialData struct {
	AAGUID              []byte
	CredentialIdLength  uint16
	CredentialId        []byte
	CredentialPublicKey *cose.Key
}

// > The PublicKeyCredentialRpEntity dictionary is used to supply additional Relying Party attributes when creating a new credential.
// https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity
type PublicKeyCredentialRpEntity struct {
	Name string `cbor:"name" json:"name"`
	ID   string `cbor:"id" json:"id"`
}

// > The PublicKeyCredentialUserEntity dictionary is used to supply additional user account attributes when creating a new credential.
// https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity
type PublicKeyCredentialUserEntity struct {
	Name        string `cbor:"name" json:"name"`
	ID          []byte `cbor:"id" json:"id"`
	DisplayName string `cbor:"displayName" json:"displayName"`
}

// This dictionary is used to supply additional parameters when creating a new credential.
// https://w3c.github.io/webauthn/#dictdef-publickeycredentialparameters
type PublicKeyCredentialParameters struct {
	Type string         `cbor:"type" json:"type"`
	Alg  cose.Algorithm `cbor:"alg" json:"alg"`
}

// > This dictionary identifies a specific public key credential.
// https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptor
type PublicKeyCredentialDescriptor struct {
	Type       string   `cbor:"type" json:"type"`
	ID         []byte   `cbor:"id" json:"id"`
	Transports []string `cbor:"transports" json:"transports"`
}

// > This is a WebAuthn optimized attestation statement format.
// https://w3c.github.io/webauthn/#sctn-packed-attestation
type PackedAttestationStatement struct {
	Alg cose.Algorithm `cbor:"alg" json:"alg"`
	Sig []byte         `cbor:"sig" json:"sig"`
	X5c [][]byte       `cbor:"x5c" json:"x5c"`
}
