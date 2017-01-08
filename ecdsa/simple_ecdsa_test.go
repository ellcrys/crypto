package ecdsa

import (
	"testing"

	"strings"

	"crypto/rand"

	. "github.com/smartystreets/goconvey/convey"
)

// TestSimpleECDSASpec test ../simple_ecdsa.go
func TestSimpleECDSASpec(t *testing.T) {

	Convey("SimpleECDSA", t, func() {

		Convey(".NewSimpleECDSA()", func() {

			Convey("should panic if called with an unsupported elliptic curve", func() {
				So(func() { NewSimpleECDSA("p224") }, ShouldPanicWith, "unsupported elliptic curve")
			})

			Convey("should not panic if called with a supported elliptic curve", func() {
				So(func() { NewSimpleECDSA("p256") }, ShouldNotPanic)
			})

		})

		Convey(".GetPubKey()", func() {
			Convey("should successfully return an ampersand delimited public key", func() {
				key := NewSimpleECDSA(CurveP256)
				pubFormatted := key.GetPubKey()
				So(pubFormatted, ShouldNotBeNil)
			})
		})

		Convey(".GenerateKey()", func() {
			Convey("should successfully generate a private key", func() {
				key := NewSimpleECDSA(CurveP256)
				currentKey := key.GetPrivKey()
				err := key.GenerateKey()
				So(err, ShouldBeNil)
				So(currentKey, ShouldNotEqual, key.GetPrivKey())
			})
		})

		Convey(".GetPrivKey()", func() {
			Convey("should successfully return a private key", func() {
				key := NewSimpleECDSA(CurveP256)
				privKey := key.GetPrivKey()
				So(privKey, ShouldNotBeNil)
			})
		})

		Convey(".LoadPrivKey()", func() {
			Convey("should load a formatted private key and use it to verify a signaturew", func() {
				key := NewSimpleECDSA(CurveP256)
				privKey := key.GetPrivKey()
				pubKey := key.GetPubKeyObj()
				loadedPrivKey, _ := LoadPrivKey(privKey, CurveP256)
				key.SetPrivKey(loadedPrivKey)
				sig, err := key.Sign(rand.Reader, []byte("hello"))
				So(err, ShouldBeNil)
				err = Verify(pubKey, []byte("hello"), []byte(sig))
				So(err, ShouldBeNil)
			})
		})

		Convey(".LoadPubKey()", func() {

			Convey("should fail if public key format is invalid", func() {
				pk, err := LoadPubKey("wrong", CurveP256)
				So(pk, ShouldBeNil)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "invalid public key. public key must have x and y coordinates")
			})

			Convey("should fail if public key x cordinate is invalid", func() {
				pk, err := LoadPubKey("wrong_x&some_y", CurveP256)
				So(pk, ShouldBeNil)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "failed to decode x coordinate")
			})

			Convey("should fail if public key y cordinate is invalid", func() {
				key := NewSimpleECDSA(CurveP256)
				pubFormatted := key.GetPubKey()
				pubKeyParts := strings.Split(pubFormatted, "&")
				pk, err := LoadPubKey(pubKeyParts[0]+"&some_y", CurveP256)
				So(pk, ShouldBeNil)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "failed to decode y coordinate")
			})

			Convey("should fail if elliptic curve is unsupported", func() {
				key := NewSimpleECDSA(CurveP256)
				pubFormatted := key.GetPubKey()
				pk, err := LoadPubKey(pubFormatted, "p224")
				So(pk, ShouldBeNil)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "unsupported elliptic curve")
			})

			Convey("should successfully load an ampersand formatted public key", func() {
				key := NewSimpleECDSA(CurveP256)
				pubFormatted := key.GetPubKey()
				pk, err := LoadPubKey(pubFormatted, CurveP256)
				So(pk, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})
		})

		Convey(".IsValidCompactPubKey", func() {

			Convey("should fail if public key is not a valid compact/formatted key", func() {
				valid, err := IsValidCompactPubKey("wrong")
				So(valid, ShouldEqual, false)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "invalid public key. public key must have x and y coordinates")
			})

			Convey("should return success if public key format is valid", func() {
				key := NewSimpleECDSA(CurveP256)
				pubFormatted := key.GetPubKey()
				valid, err := IsValidCompactPubKey(pubFormatted)
				So(valid, ShouldEqual, true)
				So(err, ShouldBeNil)
			})
		})

		Convey(".Sign()", func() {

			Convey("should successfully sign text", func() {
				key := NewSimpleECDSA(CurveP256)
				s, err := key.Sign(rand.Reader, []byte("hello"))
				So(err, ShouldBeNil)
				So(s, ShouldNotBeEmpty)
			})
		})

		Convey(".Verify()", func() {

			key := NewSimpleECDSA(CurveP256)
			s, err := key.Sign(rand.Reader, []byte("hello"))
			So(err, ShouldBeNil)

			Convey("should fail if signed hash is invalid", func() {
				key := NewSimpleECDSA(CurveP256)
				pubKey := key.privKey.PublicKey
				err := Verify(&pubKey, []byte("wrong"), []byte("wrong"))
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "invalid signed hash. expects r and s coordinates joined by an ampersand")
			})

			Convey("should fail if r cordinate could not be decoded", func() {
				key := NewSimpleECDSA(CurveP256)
				pubKey := key.privKey.PublicKey
				err := Verify(&pubKey, []byte("wrong"), []byte("wrong_r&wrong_s"))
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "failed to hex decode on r value")
			})

			Convey("should fail if s cordinate could not be decoded", func() {
				key := NewSimpleECDSA(CurveP256)
				pubKey := key.privKey.PublicKey
				sigParts := strings.Split(s, "&")
				err := Verify(&pubKey, []byte("wrong"), []byte(sigParts[0]+"&wrong_s"))
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "failed to hex decode on s value")
			})

			Convey("should fail if signature could not be verified", func() {
				key := NewSimpleECDSA(CurveP256)
				pubKey := key.privKey.PublicKey
				err := Verify(&pubKey, []byte("hi"), []byte(s))
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "verification failed")
			})

			Convey("should successfully verify signature", func() {
				pubKey := key.privKey.PublicKey
				err := Verify(&pubKey, []byte("hello"), []byte(s))
				So(err, ShouldBeNil)
			})
		})
	})
}
