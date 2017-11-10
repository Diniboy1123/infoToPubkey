package infoToPubkey

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"testing"
)

var ec_pub_string = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIsFro6K+IUxRr4yFTOTO+kFCCEvHo7B9IOMLxah6c977oFzX/beObH4a9OfosMHmft3JJZ6B3xpjIb8kduK4/A=="

func TestParsePubKey(t *testing.T) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(ec_pub_string)
	if err != nil {
		fmt.Println("public key base64 decode error")
		return
	}
	pub_key, err := Parse(pubKeyBytes)
	if err != nil {
		t.Error(err)
	}
	ECPubkey, ok := pub_key.(*ecdsa.PublicKey)
	if ok {
		t.Log(ECPubkey)
	}
}
