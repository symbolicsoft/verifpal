/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

// Implementation Version: 1.0.0

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
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

func errorCritical(errText string) {
	err := errors.New(errText)
	log.Fatal(fmt.Errorf("Error: %v.\n", err))
}

/* ---------------------------------------------------------------- *
 * ELLIPTIC CURVE CRYPTOGRAPHY                                      *
 * ---------------------------------------------------------------- */

func x25519DhFromEd25519PublicKey(private_key []byte, public_key []byte) []byte {
	var priv32 [32]byte
	var pub32 [32]byte
	var ss [32]byte
	copy(priv32[:], private_key)
	copy(pub32[:], ed25519PublicKeyToCurve25519(public_key))
	curve25519.ScalarMult(&ss, &priv32, &pub32)
	return ss[:]
}

func ed25519Gen() ([]byte, []byte) {
	public_key, private_key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		errorCritical(err.Error())
	}
	return private_key, public_key
}

func ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) []byte {
	/* SPDX-PackageCopyrightText: Copyright 2019 Google LLC
	 * SPDX-License-Identifier: BSD-3-Clause */
	var curve25519P, _ = new(big.Int).SetString(strings.Join([]string{
		"578960446186580977117854925043439539266",
		"34992332820282019728792003956564819949",
	}, ""), 10)
	bigEndianY := make([]byte, ed25519.PublicKeySize)
	for i, b := range pk {
		bigEndianY[ed25519.PublicKeySize-i-1] = b
	}
	bigEndianY[0] &= 127
	y := new(big.Int).SetBytes(bigEndianY)
	denom := big.NewInt(1)
	denom.ModInverse(denom.Sub(denom, y), curve25519P)
	u := y.Mul(y.Add(y, big.NewInt(1)), denom)
	u.Mod(u, curve25519P)
	out := make([]byte, 32)
	uBytes := u.Bytes()
	for i, b := range uBytes {
		out[len(uBytes)-i-1] = b
	}
	return out
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

func SPLIT2(b []byte) ([]byte, []byte) {
	a1 := b[00:32]
	a2 := b[32:64]
	return a1, a2
}

func SPLIT3(b []byte) ([]byte, []byte, []byte) {
	a1 := b[00:32]
	a2 := b[32:64]
	a3 := b[64:96]
	return a1, a2, a3
}

func SPLIT4(b []byte) ([]byte, []byte, []byte, []byte) {
	a1 := b[00:32]
	a2 := b[32:64]
	a3 := b[64:96]
	a4 := b[96:128]
	return a1, a2, a3, a4
}

func SPLIT5(b []byte) ([]byte, []byte, []byte, []byte, []byte) {
	a1 := b[00:32]
	a2 := b[32:64]
	a3 := b[64:96]
	a4 := b[96:128]
	a5 := b[128:160]
	return a1, a2, a3, a4, a5
}

func HASH(a ...[]byte) []byte {
	b := []byte{}
	for _, aa := range a {
		b = append(b, aa...)
	}
	h := sha256.Sum256(b)
	return h[:]
}

func MAC(k []byte, message []byte) []byte {
	mac := hmac.New(sha256.New, k)
	mac.Write(message)
	return mac.Sum(nil)
}

func HKDF1(ck []byte, ikm []byte) []byte {
	var k1 []byte
	output := hkdf.New(sha256.New, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	return k1
}

func HKDF2(ck []byte, ikm []byte) ([]byte, []byte) {
	var k1 []byte
	var k2 []byte
	output := hkdf.New(sha256.New, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	io.ReadFull(output, k2[:])
	return k1, k2
}

func HKDF3(ck []byte, ikm []byte) ([]byte, []byte, []byte) {
	var k1 []byte
	var k2 []byte
	var k3 []byte
	output := hkdf.New(sha256.New, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	io.ReadFull(output, k2[:])
	io.ReadFull(output, k3[:])
	return k1, k2, k3
}

func HKDF4(ck []byte, ikm []byte) ([]byte, []byte, []byte, []byte) {
	var k1 []byte
	var k2 []byte
	var k3 []byte
	var k4 []byte
	output := hkdf.New(sha256.New, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	io.ReadFull(output, k2[:])
	io.ReadFull(output, k3[:])
	io.ReadFull(output, k4[:])
	return k1, k2, k3, k4
}

func HKDF5(ck []byte, ikm []byte) ([]byte, []byte, []byte, []byte, []byte) {
	var k1 []byte
	var k2 []byte
	var k3 []byte
	var k4 []byte
	var k5 []byte
	output := hkdf.New(sha256.New, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	io.ReadFull(output, k2[:])
	io.ReadFull(output, k3[:])
	io.ReadFull(output, k4[:])
	io.ReadFull(output, k5[:])
	return k1, k2, k3, k4, k5
}

func PW_HASH(a ...[]byte) []byte {
	h := HASH(a...)
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
	if len(ciphertext)%aes.BlockSize != 0 {
		errorCritical("invalid ciphertext")
	}
	if len(ciphertext) < aes.BlockSize {
		errorCritical("invalid ciphertext")
	}
	iv := ciphertext[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext[aes.BlockSize:]))
	mode.CryptBlocks(plaintext, ciphertext)
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
	if len(ciphertext) <= chacha20poly1305.NonceSizeX {
		return false, plaintext
	}
	plaintext, err = enc.Open(
		nil, nonce,
		ciphertext[chacha20poly1305.NonceSizeX:], ad,
	)
	return (err == nil), plaintext
}

func PKE_ENC(pk []byte, plaintext []byte) []byte {
	esk, epk := ed25519Gen()
	ss := x25519DhFromEd25519PublicKey(esk, pk)
	ciphertext := ENC(HASH(ss), plaintext)
	return append(epk, ciphertext...)
}

func PKE_DEC(k []byte, ciphertext []byte) []byte {
	if len(ciphertext) <= 32 {
		errorCritical("invalid ciphertext")
	}
	epk := ciphertext[:32]
	ss := x25519DhFromEd25519PublicKey(k, epk)
	plaintext := DEC(HASH(ss), ciphertext)
	return plaintext
}

func SIGN(k []byte, message []byte) []byte {
	return ed25519.Sign(k, message)
}

func SIGNVERIF(pk []byte, message []byte, signature []byte) bool {
	return ed25519.Verify(pk, message, signature)
}

func RINGSIGN(ka []byte, kb []byte, kc []byte, message []byte) []byte {
	return []byte{}
}

func RINGSIGNVERIF(pka []byte, pkb []byte, pkc []byte, message []byte, signature []byte) bool {
	return false
}

func BLIND(k []byte, message []byte) []byte {
	return []byte{}
}

func UNBLIND(k []byte, message []byte, signature []byte) []byte {
	return []byte{}
}

func SHAMIR_SPLIT(x []byte) []byte {
	return []byte{}
}

func SHAMIR_JOIN(a []byte, b []byte, c []byte) []byte {
	return []byte{}
}

/* ---------------------------------------------------------------- *
 * STATE MANAGEMENT                                                 *
 * ---------------------------------------------------------------- */

/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

func main() {}
