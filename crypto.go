// This file contains crypto related functions
package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// Parse a public
func ParsePublicKey(pemBytes []byte) (*Signer, error) {

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no key found or passed in")
	}

	switch block.Type {
	case "RSA PUBLIC KEY", "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return newSigner(rsa)
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
	return nil, nil
}

// Parse a private key
func ParsePrivateKey(pemBytes []byte) (*Signer, error) {

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no key found or passed in")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return newSigner(rsa)
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
}

// creates a new signer instance with 
// rsa public or private loaded
func newSigner(k interface{}) (*Signer, error) {
	var signer *Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		signer = &Signer{ &rsa.PublicKey{}, t}
	case *rsa.PublicKey:
		signer = &Signer{ t, &rsa.PrivateKey{} }
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return signer, nil
}

type Signer struct {
	*rsa.PublicKey
	*rsa.PrivateKey
}

// Sign signs data with rsa-sha256
func (r *Signer) Sign(data []byte) (string, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
	if err == nil {
		return ToHexString(sig), nil
	}
	return "", err
}

// Verify checks the message using a rsa-sha256 signature
func (r *Signer) Verify(message []byte, hexEncodedSig string) error {
	sig, err := HexDecode(hexEncodedSig)
	if err != nil {
		return errors.New("invalid signature: unable to decode from hex to string")
	} 
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, []byte(sig))
}

// encode byte slice to base64 string
func ToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// decode a base64 string
func FromBase64(b string) (string, error) {
	bs, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s", bs), nil
}

// convert byte slice to hex string
func ToHexString(b []byte) string {
	return hex.EncodeToString(b)
}

// decode an hex string
func HexDecode(hexStr string) (string, error) {
	dst, err := hex.DecodeString(hexStr)
	return string(dst), err
}