/* SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

// Implementation Version: 0.0.1

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

// nolint:deadcode,unused
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

/* ---------------------------------------------------------------- *
 * ELLIPTIC CURVE CRYPTOGRAPHY                                      *
 * ---------------------------------------------------------------- */

func x25519DhFromEd25519PublicKey(private_key []byte, public_key []byte) ([]byte, error) {
	return curve25519.X25519(private_key, public_key)
}

func ed25519Gen() ([]byte, []byte, error) {
	public_key, private_key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return public_key, private_key, err
	}
	return private_key, public_key, nil
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

func MAC(k []byte, message []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, k)
	_, err := mac.Write(message)
	return mac.Sum(nil), err
}

func HKDF1(ck []byte, ikm []byte) ([]byte, error) {
	k1 := make([]byte, 32)
	output := hkdf.New(sha256.New, ikm, ck, []byte{})
	_, err := io.ReadFull(output, k1)
	return k1, err
}

func HKDF2(ck []byte, ikm []byte) ([]byte, []byte, error) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	output := hkdf.New(sha256.New, ikm, ck, []byte{})
	_, err := io.ReadFull(output, k1)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	_, err = io.ReadFull(output, k2)
	return k1, k2, err
}

func HKDF3(ck []byte, ikm []byte) ([]byte, []byte, []byte, error) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	k3 := make([]byte, 32)
	output := hkdf.New(sha256.New, ikm, ck, []byte{})
	_, err := io.ReadFull(output, k1)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}
	_, err = io.ReadFull(output, k2)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}
	_, err = io.ReadFull(output, k3)
	return k1, k2, k3, err
}

func HKDF4(ck []byte, ikm []byte) ([]byte, []byte, []byte, []byte, error) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	k3 := make([]byte, 32)
	k4 := make([]byte, 32)
	output := hkdf.New(sha256.New, ikm, ck, []byte{})
	_, err := io.ReadFull(output, k1)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	_, err = io.ReadFull(output, k2)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	_, err = io.ReadFull(output, k3)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	_, err = io.ReadFull(output, k4)
	return k1, k2, k3, k4, err
}

func HKDF5(ck []byte, ikm []byte) ([]byte, []byte, []byte, []byte, []byte, error) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	k3 := make([]byte, 32)
	k4 := make([]byte, 32)
	k5 := make([]byte, 32)
	output := hkdf.New(sha256.New, ikm, ck, []byte{})
	_, err := io.ReadFull(output, k1)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	_, err = io.ReadFull(output, k2)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	_, err = io.ReadFull(output, k3)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	_, err = io.ReadFull(output, k4)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	_, err = io.ReadFull(output, k5)
	return k1, k2, k3, k4, k5, err
}

func PW_HASH(a ...[]byte) ([]byte, error) {
	h := HASH(a...)
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return []byte{}, err
	}
	dk, err := scrypt.Key(h, salt, 32768, 8, 1, 32)
	return dk, err
}

func ENC(k []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return []byte{}, err
	}
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return []byte{}, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return append(iv, ciphertext...), nil
}

func DEC(k []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return []byte{}, err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return []byte{}, fmt.Errorf("invalid ciphertext")
	}
	if len(ciphertext) < aes.BlockSize {
		return []byte{}, fmt.Errorf("invalid ciphertext")
	}
	iv := ciphertext[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext[aes.BlockSize:]))
	mode.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

func AEAD_ENC(k []byte, plaintext []byte, ad []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	_, err := rand.Read(nonce)
	if err != nil {
		return []byte{}, err
	}
	enc, _ := chacha20poly1305.NewX(k)
	ciphertext := enc.Seal(nil, nonce, plaintext, ad)
	return append(nonce, ciphertext...), nil
}

func AEAD_DEC(k []byte, ciphertext []byte, ad []byte) ([]byte, error) {
	enc, err := chacha20poly1305.NewX(k)
	if err != nil {
		return []byte{}, err
	}
	nonce := ciphertext[:chacha20poly1305.NonceSizeX]
	if len(ciphertext) <= chacha20poly1305.NonceSizeX {
		return []byte{}, fmt.Errorf("authenticated decryption failed")
	}
	plaintext, err := enc.Open(
		nil, nonce,
		ciphertext[chacha20poly1305.NonceSizeX:], ad,
	)
	return plaintext, err
}

func PKE_ENC(pk []byte, plaintext []byte) ([]byte, error) {
	esk, epk, err := ed25519Gen()
	if err != nil {
		return []byte{}, err
	}
	ss, err := x25519DhFromEd25519PublicKey(esk, pk)
	if err != nil {
		return []byte{}, err
	}
	ciphertext, err := ENC(HASH(ss), plaintext)
	return append(epk, ciphertext...), err
}

func PKE_DEC(k []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) <= 32 {
		return []byte{}, fmt.Errorf("invalid ciphertext")
	}
	epk := ciphertext[:32]
	ss, err := x25519DhFromEd25519PublicKey(k, epk)
	if err != nil {
		return []byte{}, err
	}
	plaintext, err := DEC(HASH(ss), ciphertext)
	return plaintext, err
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
