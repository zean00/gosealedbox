package gosealedbox

import (
	"crypto/rand"
	"testing"

	"github.com/jamesruan/sodium"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
)

func TestBox(t *testing.T) {
	pk, sk, _ := box.GenerateKey(rand.Reader)

	msg := []byte("Test Box Seal")

	out, err := BoxSeal(msg, pk)
	assert.NoError(t, err, "Should no error")

	omsg, r := BoxSealOpen(out, pk, sk)
	assert.Equal(t, msg, omsg, "Should be equal")
	assert.True(t, r, "Should be true")
}

func TestBoxSodium(t *testing.T) {
	kp := sodium.MakeBoxKP()
	msg := []byte("Test Box Seal")
	out := sodium.Bytes(msg).SealedBox(kp.PublicKey)

	pkb := kp.PublicKey.Bytes
	skb := kp.SecretKey.Bytes
	var pk, sk [32]byte
	copy(pk[:], pkb[:])
	copy(sk[:], skb[:])
	omsg, r := BoxSealOpen(out, &pk, &sk)
	assert.Equal(t, msg, omsg, "Should be equal")
	assert.True(t, r, "Should be true")
}

func TestSodiumBox(t *testing.T) {
	pk, sk, _ := box.GenerateKey(rand.Reader)
	msg := []byte("Test Box Seal")

	spk := sodium.BoxPublicKey{Bytes: pk[:]}
	ssk := sodium.BoxSecretKey{Bytes: sk[:]}
	kp := sodium.BoxKP{PublicKey: spk, SecretKey: ssk}

	out, err := BoxSeal(msg, pk)
	assert.NoError(t, err, "Should no error")

	omsg, err := sodium.Bytes(out).SealedBoxOpen(kp)
	assert.NoError(t, err, "Should no error")
	assert.Equal(t, msg, []byte(omsg), "Should be equal")
}

func TestBoxMix(t *testing.T) {
	kp := sodium.MakeBoxKP()
	msg := []byte("Test Box Seal")
	pkb := kp.PublicKey.Bytes
	var pk [32]byte
	copy(pk[:], pkb[:])

	out, err := BoxSeal(msg, &pk)
	assert.NoError(t, err, "Should no error")

	omsg, err := sodium.Bytes(out).SealedBoxOpen(kp)
	assert.NoError(t, err, "Should no error")
	assert.Equal(t, msg, []byte(omsg), "Should be equal")
}

func TestBoxMix2(t *testing.T) {
	pk, sk, _ := box.GenerateKey(rand.Reader)
	msg := []byte("Test Box Seal")

	spk := sodium.BoxPublicKey{Bytes: pk[:]}
	out := sodium.Bytes(msg).SealedBox(spk)

	omsg, r := BoxSealOpen(out, pk, sk)
	assert.Equal(t, msg, omsg, "Should be equal")
	assert.True(t, r, "Should be true")
}

func TestEd25519(t *testing.T) {
	kp := sodium.MakeSignKP()
	msg := []byte("Test Signature ")
	sign := sodium.Bytes(msg).Sign(kp.SecretKey)

	sk := ed25519.PrivateKey(kp.SecretKey.Bytes)
	esign := SignMessage(sk, msg)
	assert.Equal(t, []byte(sign), esign)
}

func TestSodiumEd(t *testing.T) {
	kp := sodium.MakeSignKP()
	msg := []byte("Test Signature ")
	sign := sodium.Bytes(msg).Sign(kp.SecretKey)
	pk := ed25519.PublicKey(kp.PublicKey.Bytes)
	emsg, r := SignMessageOpen(pk, sign)
	assert.True(t, r)
	assert.Equal(t, msg, emsg)
}

func TestEdSodium(t *testing.T) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("Test Signature ")
	emsg := SignMessage(sk, msg)
	spk := sodium.SignPublicKey{Bytes: []byte(pk)}
	omsg, err := sodium.Bytes(emsg).SignOpen(spk)
	assert.NoError(t, err)
	assert.Equal(t, msg, []byte(omsg))
}
