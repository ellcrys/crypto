package ecdsa

// Simple ECDSA makes available convenient
// methods to allow simple and less technical
// use of Elliptic curve encryption. For example,
// The use of ampersand as a separator when concantenating
// x and y coordinates or for the r and s signature pairs.
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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

const (
	// CurveP256 P256 elliptic curve
	CurveP256 = "p256"
)

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

	var curve elliptic.Curve
	switch curveName {
	case CurveP256:
		curve = elliptic.P256()
	default:
		return nil, errors.New("unsupported elliptic curve")
	}

	return &goecdsa.PrivateKey{
		PublicKey: goecdsa.PublicKey{Curve: curve},
		D:         new(big.Int).SetBytes(dBytes),
	}, nil
}

// LoadPubKey creates a public key object from compact
// x and y cordinates contantenated by an ampersand.
func LoadPubKey(pubKey string, curveName string) (*goecdsa.PublicKey, error) {

	pubKeySplit := strings.Split(pubKey, "&")
	if len(pubKeySplit) != 2 {
		return nil, errors.New("invalid public key. public key must have x and y coordinates")
	}

	x := pubKeySplit[0]
	y := pubKeySplit[1]

	xByte, err := hex.DecodeString(x)
	if err != nil {
		return nil, errors.New("failed to decode x coordinate")
	}

	yByte, err := hex.DecodeString(y)
	if err != nil {
		return nil, errors.New("failed to decode y coordinate")
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
		X:     new(big.Int).SetBytes(xByte),
		Y:     new(big.Int).SetBytes(yByte),
	}, nil
}

// GetPubKey gets the compact version of the public key
// created in the current instance.
// of a 1-byte descriptor indicating the uncompressed
// form of the public key
func (se *SimpleECDSA) GetPubKey() string {
	x := se.privKey.Public().(*goecdsa.PublicKey).X
	y := se.privKey.Public().(*goecdsa.PublicKey).Y
	return fmt.Sprintf("%s&%s", hex.EncodeToString(x.Bytes()), hex.EncodeToString(y.Bytes()))
}

// GetPubKeyObj returns the public key object
func (se *SimpleECDSA) GetPubKeyObj() *goecdsa.PublicKey {
	return &se.privKey.PublicKey
}

// GetPrivKey returns the private key
func (se *SimpleECDSA) GetPrivKey() string {
	return fmt.Sprintf("%s", hex.EncodeToString(se.privKey.D.Bytes()))
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

// Sign a byte slice. Return the a signature
// comprising of the r and s pairs concantenated by an
// ampersand character
func (se *SimpleECDSA) Sign(rand io.Reader, hashed []byte) (string, error) {
	r, s, err := goecdsa.Sign(rand, se.privKey, hashed)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s&%s", hex.EncodeToString(r.Bytes()), hex.EncodeToString(s.Bytes())), nil
}

// IsValidCompactPubKey checks whether the public key
// is a valid compact public key format.
func IsValidCompactPubKey(pubKey string) (bool, error) {
	if len(strings.Split(pubKey, "&")) != 2 {
		return false, errors.New("invalid public key. public key must have x and y coordinates")
	}
	return true, nil
}

// Verify a signature. Expects a signature composed of
// the Elliptic curve r and s pairs concantenated by an
// ampersand character (&).
func Verify(pubKey *goecdsa.PublicKey, hash []byte, sig []byte) error {

	// get r and s individual values from signature
	sigSplit := strings.Split(string(sig), "&")
	if len(sigSplit) != 2 {
		return errors.New("invalid signed hash. expects r and s coordinates joined by an ampersand")
	}

	rByte, err := hex.DecodeString(sigSplit[0])
	if err != nil {
		return errors.New("failed to hex decode on r value")
	}

	sByte, err := hex.DecodeString(sigSplit[1])
	if err != nil {
		return errors.New("failed to hex decode on s value")
	}

	// verify signature
	if goecdsa.Verify(
		pubKey, hash,
		new(big.Int).SetBytes(rByte),
		new(big.Int).SetBytes(sByte)) {
		return nil
	}
	return errors.New("verification failed")
}
