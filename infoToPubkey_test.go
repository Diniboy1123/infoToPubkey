package infoToPubkey

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"testing"
)

var ec_pub_string = []string{
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIsFro6K+IUxRr4yFTOTO+kFCCEvHo7B9IOMLxah6c977oFzX/beObH4a9OfosMHmft3JJZ6B3xpjIb8kduK4/A==",
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENnoaYTAh15xpR65XRw7jHYj7vNUIGu5I4OmLCrORWwdjrcrED+bJo+nF2HyA5hnH12Dqt1bR8mqKBXynG3HBNw==",
}

func TestParsePubKey(t *testing.T) {
	for _, pub_string := range ec_pub_string {
		pubKeyBytes, err := base64.StdEncoding.DecodeString(pub_string)
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
			t.Log(ECPubkey.Curve)
		} else {
			t.Error("conver to ec key error")
		}
	}

}
