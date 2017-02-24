package gosealedbox

import (
	"crypto/rand"
	"errors"

	ex "github.com/agl/ed25519/extra25519"
	"github.com/dchest/blake2b"
	"golang.org/x/crypto/curve25519"
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

//SignKeyToBox convert pair of signature key to pair of box key (secret, public, error)
func SignKeyToBox(privateKey, publicKey []byte) (*[32]byte, *[32]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("Invalid private key length")
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, errors.New("Invalid public key length")
	}

	var sk, pk, spk *[32]byte
	var ssk [64]byte
	copy(ssk[:], privateKey[0:64])
	copy(spk[:], publicKey[0:32])
	ex.PrivateKeyToCurve25519(sk, &ssk)
	ex.PublicKeyToCurve25519(pk, spk)
	return sk, pk, nil
}

//PrivateSignToBox convert signature private key to box key pair (secret, public, error)
func PrivateSignToBox(privateKey []byte) (*[32]byte, *[32]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("Invalid private key length")
	}
	pk := ed25519.PrivateKey(privateKey).Public()
	bpk := pk.(ed25519.PublicKey)
	return SignKeyToBox(privateKey, []byte(bpk))
}

//ToPublic convert box secret key to public key
func ToPublic(privateKey *[32]byte) *[32]byte {
	var pk *[32]byte
	curve25519.ScalarBaseMult(pk, privateKey)
	return pk
}
