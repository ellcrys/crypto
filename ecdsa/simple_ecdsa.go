package ecdsa

// Simple ECDSA supports creation of keypair,
// signing and verification. Public Key, Private Key and Signatures
// are ASN.1/DER encoded.
//
// Examples
//
// ecd := NewSimpleECDSA()
// ecd.GenerateKey()
// pubKey, _ := LoadPubKey(ecd.GetPubKey())
// fmt.Println("Private Key: ", ecd.GetPrivKey())
// signature, _ := ecd.Sign(rand.Reader, []byte("hello"))
// verified := Verify(pubKey, []byte("hello"), []byte(signature))

import (
	goecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const (
	// CurveP256 P256 elliptic curve
	CurveP256 = "p256"
)

// ASN1PubKey defines a public key structure for ANS.1/DER encoding
type ASN1PubKey struct {
	X []byte
	Y []byte
}

// ASN1PrivKey defines a private key structure for ANS.1/DER encoding
type ASN1PrivKey struct {
	D []byte
}

// ASN1Sig defines an elliptic signature for ANS.1/DER encoding
type ASN1Sig struct {
	R []byte
	S []byte
}

// SimpleECDSA defines code for creating ECDSA keys,
// signing and verifying data.
type SimpleECDSA struct {
	curve   elliptic.Curve
	privKey *goecdsa.PrivateKey
}

// NewSimpleECDSA creates a new SimpleECDSA object
func NewSimpleECDSA(curveName string) *SimpleECDSA {
	var curve elliptic.Curve
	switch curveName {
	case CurveP256:
		curve = elliptic.P256()
	default:
		panic("unsupported elliptic curve")
	}
	var se = &SimpleECDSA{curve: curve}
	if err := se.GenerateKey(); err != nil {
		panic(err)
	}
	return se
}

// LoadPrivKey a formatted private key and return a ecdsa.PrivateKey
func LoadPrivKey(privKey, curveName string) (*goecdsa.PrivateKey, error) {

	dBytes, err := hex.DecodeString(privKey)
	if err != nil {
		return nil, errors.New("failed to decode private key")
	}

	var asn1PrivKey ASN1PrivKey
	_, err = asn1.Unmarshal(dBytes, &asn1PrivKey)
	if err != nil {
		return nil, errors.New("failed to unmarshal ASN.1/DER private key")
	}

	var curve elliptic.Curve
	switch curveName {
	case CurveP256:
		curve = elliptic.P256()
	default:
		return nil, errors.New("unsupported elliptic curve")
	}

	return &goecdsa.PrivateKey{
		PublicKey: goecdsa.PublicKey{Curve: curve},
		D:         new(big.Int).SetBytes(asn1PrivKey.D),
	}, nil
}

// LoadPubKey creates a public key object and returns
// an ASN.1/DER encoded string.
func LoadPubKey(pubKey string, curveName string) (*goecdsa.PublicKey, error) {

	pubBS, err := hex.DecodeString(pubKey)
	if err != nil {
		return nil, errors.New("failed to hex decode public key")
	}

	var asn1Pub ASN1PubKey
	_, err = asn1.Unmarshal(pubBS, &asn1Pub)
	if err != nil {
		return nil, errors.New("failed to unmarshal ASN.1/DER public key")
	}

	var curve elliptic.Curve
	switch curveName {
	case CurveP256:
		curve = elliptic.P256()
	default:
		return nil, errors.New("unsupported elliptic curve")
	}

	return &goecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(asn1Pub.X),
		Y:     new(big.Int).SetBytes(asn1Pub.Y),
	}, nil
}

// GetPubKey encodes the public key in a DER-encoded ASN.1 data structure
// returns the hex encoded value.
func (se *SimpleECDSA) GetPubKey() string {
	asn1PubKey := ASN1PubKey{
		X: se.privKey.Public().(*goecdsa.PublicKey).X.Bytes(),
		Y: se.privKey.Public().(*goecdsa.PublicKey).Y.Bytes(),
	}
	bs, err := asn1.Marshal(asn1PubKey)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s", hex.EncodeToString(bs))
}

// GetPubKeyObj returns the public key object
func (se *SimpleECDSA) GetPubKeyObj() *goecdsa.PublicKey {
	return &se.privKey.PublicKey
}

// GetPrivKey returns an ASN.1/DER encoded private key
func (se *SimpleECDSA) GetPrivKey() string {
	var asn1PrivKey = ASN1PrivKey{
		D: se.privKey.D.Bytes(),
	}
	bs, err := asn1.Marshal(asn1PrivKey)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s", hex.EncodeToString(bs))
}

// GenerateKey creates a new ECDSA private key
func (se *SimpleECDSA) GenerateKey() error {

	privKey, err := goecdsa.GenerateKey(se.curve, rand.Reader)
	if err != nil {
		return err
	}

	se.privKey = privKey
	return nil
}

// SetPrivKey sets the private key
func (se *SimpleECDSA) SetPrivKey(privKey *goecdsa.PrivateKey) {
	se.privKey = privKey
}

// Sign a byte slice. Return a ASN.1/DER-encoded signature
func (se *SimpleECDSA) Sign(rand io.Reader, hashed []byte) (string, error) {
	r, s, err := goecdsa.Sign(rand, se.privKey, hashed)
	if err != nil {
		return "", err
	}

	var asn1Sig = ASN1Sig{
		R: r.Bytes(),
		S: s.Bytes(),
	}

	bs, _ := asn1.Marshal(asn1Sig)

	return fmt.Sprintf("%s", hex.EncodeToString(bs)), nil
}

// IsValidCompactPubKey checks whether the public key
// pass hex and ASN.1/DER decoding operations.
func IsValidCompactPubKey(pubKey string) (bool, error) {

	pubBS, err := hex.DecodeString(pubKey)
	if err != nil {
		return false, errors.New("failed to hex decode public key")
	}

	var asn1Pub ASN1PubKey
	_, err = asn1.Unmarshal(pubBS, &asn1Pub)
	if err != nil {
		return false, errors.New("failed to unmarshal ASN.1/DER public key")
	}

	return true, nil
}

// Verify a signature. Expects a ASN.1/DER encoded signature
func Verify(pubKey *goecdsa.PublicKey, hash []byte, sig []byte) error {

	decSig, err := hex.DecodeString(string(sig))
	if err != nil {
		return errors.New("failed to hex decode signature")
	}

	var asn1Sig ASN1Sig
	_, err = asn1.Unmarshal(decSig, &asn1Sig)
	if err != nil {
		return errors.New("failed to unmarshal ASN.1/DER signature")
	}

	// verify signature
	if goecdsa.Verify(
		pubKey, hash,
		new(big.Int).SetBytes(asn1Sig.R),
		new(big.Int).SetBytes(asn1Sig.S)) {
		return nil
	}
	return errors.New("verification failed")
}
