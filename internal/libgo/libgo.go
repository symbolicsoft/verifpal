// Implementation Version: 1.0.0

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

package main

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
	"hash"
	"io"
	"math"
)

/* ---------------------------------------------------------------- *
 * TYPES                                                            *
 * ---------------------------------------------------------------- */

/* ---------------------------------------------------------------- *
 * CONSTANTS                                                        *
 * ---------------------------------------------------------------- */

var emptyKey = []byte{
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

var minNonce = uint32(0)

/* ---------------------------------------------------------------- *
 * UTILITY FUNCTIONS                                                *
 * ---------------------------------------------------------------- */

func getPublicKey(kp *keypair) []byte {
	return kp.public_key
}

func isEmptyKey(k []byte) bool {
	return subtle.ConstantTimeCompare(k[:], emptyKey[:]) == 1
}

func errorCritical(errText string) {
	err := errors.New(errText)
	log.Fatal(fmt.Errorf("Error: %v.\n", err))
}

func validatePublicKey(k []byte) bool {
	forbiddenCurveValues := [12][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0},
		{95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87},
		{236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{205, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 128},
		{76, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 215},
		{217, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{218, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{219, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 25},
	}
	for _, testValue := range forbiddenCurveValues {
		if subtle.ConstantTimeCompare(k[:], testValue[:]) == 1 {
			panic("Invalid public key")
		}
	}
	return true
}

/* ---------------------------------------------------------------- *
 * PRIMITIVES                                                       *
 * ---------------------------------------------------------------- */


func ASSERT(a []byte, b []byte) bool {
	return hmac.Equal(a, b)
}

func CONCAT(a ...[]byte) []byte {
	b := []byte{}
	for _, aa := range a {
		b = append(b, aa...)
	}
	return b
}

func SPLIT(b []byte) []byte {
	return b...
}

func HASH(a ...[]byte) []byte {
	b := []byte{}
	for _, aa := range a {
		b = append(b, aa...)
	}
	return blake2s.Sum256(b)
}

func MAC(k []byte, message []byte) bool {
	mac := hmac.New(blake2s.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func HKDF1(ck []byte, ikm []byte) ([]byte) {
	h, _ := blake2s.New256([]byte{})
	var k1 []byte
	output := hkdf.New(h, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	return k1
}

func HKDF2(ck []byte, ikm []byte) ([]byte, []byte) {
	h, _ := blake2s.New256([]byte{})
	var k1 []byte
	var k2 []byte
	output := hkdf.New(h, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	io.ReadFull(output, k2[:])
	return k1, k2
}

func HKDF3(ck []byte, ikm []byte) ([]byte, []byte, []byte) {
	h, _ := blake2s.New256([]byte{})
	var k1 []byte
	var k2 []byte
	var k3 []byte
	output := hkdf.New(h, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	io.ReadFull(output, k2[:])
	io.ReadFull(output, k3[:])
	return k1, k2, k3
}

func HKDF4(ck []byte, ikm []byte) ([]byte, []byte, []byte, []byte) {
	h, _ := blake2s.New256([]byte{})
	var k1 []byte
	var k2 []byte
	var k3 []byte
	var k4 []byte
	output := hkdf.New(h, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	io.ReadFull(output, k2[:])
	io.ReadFull(output, k3[:])
	io.ReadFull(output, k4[:])
	return k1, k2, k3, k4
}

func HKDF5(ck []byte, ikm []byte) ([]byte, []byte, []byte, []byte, []byte) {
	h, _ := blake2s.New256([]byte{})
	var k1 []byte
	var k2 []byte
	var k3 []byte
	var k4 []byte
	var k5 []byte
	output := hkdf.New(h, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	io.ReadFull(output, k2[:])
	io.ReadFull(output, k3[:])
	io.ReadFull(output, k4[:])
	io.ReadFull(output, k5[:])
	return k1, k2, k3, k4, k5
}

func PW_HASH(a ...[]byte) []byte {
	h := HASH(a)
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		errorCritical(err.Error())
	}
	dk, err := scrypt.Key(h, salt, 32768, 8, 1, 32)
	if err != nil {
		errorCritical(err.Error())
	}
	return dk
}

func ENC(k []byte, plaintext []byte) []byte {
	plaintext, err := pkcs7.Pad(plaintext, aes.BlockSize)
	if err =! nil {
		errorCritical(err.Error())
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		errorCritical(err.Error())
	}
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		errorCritical(err.Error())
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return append(iv, ciphertext...)
}

func DEC(k []byte, ciphertext []byte) []byte {
	block, err := aes.NewCipher(k)
	if err != nil {
		errorCritical(err.Error())
	}
	if len(ciphertext) % aes.BlockSize != 0 {
		errorCritical("invalid ciphertext")
	}
	if len(ciphertext) < aes.BlockSize {
		errorCritical("invalid ciphertext")
	}
	iv := ciphertext[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext[aes.BlockSize:]))
	mode.CryptBlocks(plaintext, ciphertext)
	plaintext, _ = pkcs7.Unpad(plaintext, aes.BlockSize)
	return plaintext
}

func AEAD_ENC(k []byte, plaintext []byte, ad []byte) []byte {
	ciphertext := []byte{}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	_, err := rand.Read(nonce)
	if err != nil {
		errorCritical(err.Error())
	}
	enc, _ := chacha20poly1305.NewX(k[:])
	ciphertext = enc.Seal(nil, nonce, plaintext, ad)
	return append(nonce, ciphertext...)
}

func AEAD_DEC(k []byte, ciphertext []byte, ad []byte) (bool, []byte) {
	plaintext := []byte{}
	enc, err := chacha20poly1305.NewX(k[:])
	nonce := ciphertext[:chacha20poly1305.NonceSizeX]
	if len(ciphertext) < chacha20poly1305.NonceSizeX + 1 {
		return err.Error("invalid ciphertext"), plaintext
	}
	plaintext, err = enc.Open(
		nil, nonce,
		ciphertext[chacha20poly1305.NonceSizeX:], ad,
	)
	return (err == nil), plaintext
}

func PKE_ENC(k []byte, plaintext []byte) []byte {

}

func PKE_DEC(k []byte, ciphertext []byte) []byte {

}

func SIGN(k []byte, message []byte) []byte {

}

func SIGNVERIF(k []byte, message []byte, signature []byte) bool {

}

func RINGSIGN(ka []byte, kb []byte, kc []byte, message []byte) []byte {

}

func RINGSIGNVERIF(ka []byte, kb []byte, kc []byte, message []byte, signature []byte) bool {

}

func BLIND(k []byte, message []byte) []byte {

}

func UNBLIND(k []byte, message []byte, signature []byte) []byte {

}

func SHAMIR_SPLIT(x []byte) []byte {

}

func SHAMIR_JOIN(a []byte, b []byte, c []byte) []byte {

}

func dh(private_key []byte, public_key []byte) []byte {
	var ss []byte
	curve25519.ScalarMult(&ss, &private_key, &public_key)
	return ss
}

func generateKeypair() keypair {
	var public_key []byte
	var private_key []byte
	_, _ = rand.Read(private_key[:])
	curve25519.ScalarBaseMult(&public_key, &private_key)
	if validatePublicKey(public_key[:]) {
		return keypair{public_key, private_key}
	}
	return generateKeypair()
}

func generatePublicKey(private_key []byte) []byte {
	var public_key []byte
	curve25519.ScalarBaseMult(&public_key, &private_key)
	return public_key
}

/* ---------------------------------------------------------------- *
 * STATE MANAGEMENT                                                 *
 * ---------------------------------------------------------------- */


/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

func main() {}
