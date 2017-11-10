package infoToPubkey

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
)

var (
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type pkcs1PublicKey struct {
	N *big.Int
	E int
}
type dsaAlgorithmParameters struct {
	P, Q, G *big.Int
}

func Parse(infoBytes []byte) (interface{}, error) {
	var sbjInfo subjectPublicKeyInfo
	_, err := asn1.Unmarshal(infoBytes, &sbjInfo)
	if err != nil {
		return nil, err
	}
	return getPublicKeyFromSubjectPublicKeyInfo(sbjInfo)
}

func getPublicKeyFromSubjectPublicKeyInfo(subjInfo subjectPublicKeyInfo) (interface{}, error) {
	algo := getPublicKeyAlgorithmFromOID(subjInfo.Algorithm.Algorithm)
	if algo == x509.UnknownPublicKeyAlgorithm {
		return nil, errors.New("x509: unknown public key algorithm")
	}

	asn1Data := subjInfo.PublicKey.RightAlign()
	switch algo {
	case x509.RSA:
		// RSA public keys must have a NULL in the parameters
		// (https://tools.ietf.org/html/rfc3279#section-2.3.1).
		if !bytes.Equal(subjInfo.Algorithm.Parameters.FullBytes, asn1.NullBytes) {
			return nil, errors.New("x509: RSA key missing NULL parameters")
		}

		p := new(pkcs1PublicKey)
		rest, err := asn1.Unmarshal(asn1Data, p)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after RSA public key")
		}

		if p.N.Sign() <= 0 {
			return nil, errors.New("x509: RSA modulus is not a positive number")
		}
		if p.E <= 0 {
			return nil, errors.New("x509: RSA public exponent is not a positive number")
		}

		pub := &rsa.PublicKey{
			E: p.E,
			N: p.N,
		}
		return pub, nil
	case x509.DSA:
		var p *big.Int
		rest, err := asn1.Unmarshal(asn1Data, &p)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after DSA public key")
		}
		paramsData := subjInfo.Algorithm.Parameters.FullBytes
		params := new(dsaAlgorithmParameters)
		rest, err = asn1.Unmarshal(paramsData, params)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after DSA parameters")
		}
		if p.Sign() <= 0 || params.P.Sign() <= 0 || params.Q.Sign() <= 0 || params.G.Sign() <= 0 {
			return nil, errors.New("x509: zero or negative DSA parameter")
		}
		pub := &dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: params.P,
				Q: params.Q,
				G: params.G,
			},
			Y: p,
		}
		return pub, nil
	case x509.ECDSA:
		paramsData := subjInfo.Algorithm.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after ECDSA parameters")
		}
		namedCurve := namedCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil, errors.New("x509: unsupported elliptic curve")
		}
		x, y := elliptic.Unmarshal(namedCurve, asn1Data)
		if x == nil {
			return nil, errors.New("x509: failed to unmarshal elliptic curve point")
		}
		pub := &ecdsa.PublicKey{
			Curve: namedCurve,
			X:     x,
			Y:     y,
		}
		return pub, nil
	default:
		return nil, nil
	}
}

func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.PublicKeyAlgorithm {
	switch {
	case oid.Equal(oidPublicKeyRSA):
		return x509.RSA
	case oid.Equal(oidPublicKeyDSA):
		return x509.DSA
	case oid.Equal(oidPublicKeyECDSA):
		return x509.ECDSA
	}
	return x509.UnknownPublicKeyAlgorithm
}

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}
