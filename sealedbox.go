package gosealedbox

import (
	"crypto/rand"

	"github.com/dchest/blake2b"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
)

//BoxSeal encrypt message
func BoxSeal(message []byte, peersPublicKey *[32]byte) ([]byte, error) {
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nonce, err := calculateNonce(pk, peersPublicKey)
	if err != nil {
		return nil, err
	}
	enc := box.Seal(nil, message, nonce, peersPublicKey, sk)
	return append(pk[:], enc...), nil
}

//BoxSealOpen decrypt message
func BoxSealOpen(boxmsg []byte, publicKey, privateKey *[32]byte) ([]byte, bool) {
	var pk [32]byte
	copy(pk[:], boxmsg[0:32])
	crypted := boxmsg[32:]
	nonce, err := calculateNonce(&pk, publicKey)
	if err != nil {
		return nil, false
	}
	return box.Open(nil, crypted, nonce, &pk, privateKey)
}

func calculateNonce(publicKey, peersPublicKey *[32]byte) (*[24]byte, error) {
	var nonce [24]byte
	comb := append(publicKey[:], peersPublicKey[:]...)
	h, err := blake2b.New(&blake2b.Config{Size: 24})
	if err != nil {
		return &nonce, err
	}
	h.Write(comb)
	hash := h.Sum(nil)
	copy(nonce[:], hash[:])
	return &nonce, nil
}

//SignMessage sign message and return signed message
func SignMessage(privateKey ed25519.PrivateKey, message []byte) []byte {
	s := ed25519.Sign(privateKey, message)
	return append(s, message...)
}

//SignMessageOpen verify signed message and return message
func SignMessageOpen(publicKey ed25519.PublicKey, sigmsg []byte) ([]byte, bool) {
	if len(sigmsg) <= 64 {
		return nil, false
	}
	s := sigmsg[0:64]
	m := sigmsg[64:]
	r := ed25519.Verify(publicKey, m, s)
	if !r {
		m = nil
	}
	return m, r
}
