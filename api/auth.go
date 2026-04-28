package api

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrdecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	sdktypes "github.com/lighthouse-web3/baas-go-sdk/types"
	"golang.org/x/crypto/sha3"
)

// APIKeyPrefix is the prefix every Lighthouse API key carries.
const APIKeyPrefix = "lh_"

// HasAPIKeyPrefix reports whether the given token looks like a Lighthouse API key.
func HasAPIKeyPrefix(token string) bool {
	return strings.HasPrefix(token, APIKeyPrefix)
}

// WalletAdapter abstracts Ethereum wallet operations for SIWE.
type WalletAdapter struct {
	Address     string
	SignMessage func(message string) (string, error)
}

func WalletFromPrivateKey(privateKeyHex string) (*WalletAdapter, error) {
	privKey, err := parsePrivateKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	addr := addressFromPubKey(privKey.PubKey())

	return &WalletAdapter{
		Address: addr,
		SignMessage: func(message string) (string, error) {
			return signPersonalMessage(privKey, message)
		},
	}, nil
}

func WalletFromSigner(address string, signFn func(string) (string, error)) *WalletAdapter {
	return &WalletAdapter{
		Address:     address,
		SignMessage: signFn,
	}
}

// Authenticate performs the full SIWE authentication flow and stores JWT.
func Authenticate(http *HttpClient, wallet *WalletAdapter) (string, error) {
	nonce, err := http.RequestNonce(strings.ToLower(wallet.Address))
	if err != nil {
		return "", fmt.Errorf("request nonce: %w", err)
	}

	siweMsg := buildSIWEMessage(
		nonce.Domain,
		wallet.Address,
		"Sign in to Lighthouse Backup",
		nonce.URI,
		"1",
		nonce.ChainID,
		nonce.Nonce,
		time.Now().UTC().Format(time.RFC3339),
	)

	signature, err := wallet.SignMessage(siweMsg)
	if err != nil {
		return "", fmt.Errorf("sign message: %w", err)
	}

	authResp, err := http.VerifySIWE(siweMsg, signature)
	if err != nil {
		return "", fmt.Errorf("verify siwe: %w", err)
	}

	http.SetToken(authResp.Token)
	return authResp.Token, nil
}

func RegisterWithEmail(http *HttpClient, email, password, displayName string) (sdktypes.EmailRegisterResponse, error) {
	return http.EmailRegister(sdktypes.EmailRegisterRequest{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
	})
}

func VerifyEmail(http *HttpClient, req sdktypes.EmailVerifyRequest) (sdktypes.EmailVerifyResponse, error) {
	resp, err := http.EmailVerify(req)
	if err != nil {
		return resp, err
	}
	if resp.Token != "" {
		http.SetToken(resp.Token)
	}
	return resp, nil
}

func LoginWithEmail(http *HttpClient, email, password string) (sdktypes.AuthResponse, error) {
	resp, err := http.EmailLogin(sdktypes.EmailLoginRequest{Email: email, Password: password})
	if err != nil {
		return resp, err
	}
	if resp.Token != "" {
		http.SetToken(resp.Token)
	}
	return resp, nil
}

func LinkWalletIdentity(http *HttpClient, walletAddress string) (sdktypes.LinkIdentityResponse, error) {
	return http.LinkIdentity(sdktypes.LinkIdentityRequest{
		Provider:        "siwe",
		ProviderSubject: strings.ToLower(walletAddress),
	})
}

func LinkEmailIdentity(http *HttpClient, email, password string) (sdktypes.LinkIdentityResponse, error) {
	return http.LinkIdentity(sdktypes.LinkIdentityRequest{
		Provider:        "email_password",
		ProviderSubject: email,
		Password:        password,
	})
}

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

func personalSignHash(msg []byte) []byte {
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msg))
	return keccak256(append([]byte(prefix), msg...))
}

func parsePrivateKey(hexKey string) (*secp256k1.PrivateKey, error) {
	hexKey = strings.TrimPrefix(hexKey, "0x")
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	return secp256k1.PrivKeyFromBytes(b), nil
}

func addressFromPubKey(pubKey *secp256k1.PublicKey) string {
	uncompressed := pubKey.SerializeUncompressed()
	hash := keccak256(uncompressed[1:])
	addr := hex.EncodeToString(hash[12:])
	return toChecksumAddress(addr)
}

func toChecksumAddress(addrLower string) string {
	addrLower = strings.TrimPrefix(strings.ToLower(addrLower), "0x")
	hash := hex.EncodeToString(keccak256([]byte(addrLower)))

	result := "0x"
	for i, c := range addrLower {
		if c >= '0' && c <= '9' {
			result += string(c)
		} else {
			if hash[i] >= '8' {
				result += strings.ToUpper(string(c))
			} else {
				result += string(c)
			}
		}
	}
	return result
}

func signPersonalMessage(privKey *secp256k1.PrivateKey, message string) (string, error) {
	hash := personalSignHash([]byte(message))
	sig := dcrdecdsa.SignCompact(privKey, hash, false)

	ethSig := make([]byte, 65)
	copy(ethSig[0:32], sig[1:33])
	copy(ethSig[32:64], sig[33:65])
	ethSig[64] = sig[0]

	return "0x" + hex.EncodeToString(ethSig), nil
}

func buildSIWEMessage(domain, address, statement, uri, version string, chainID int, nonce, issuedAt string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s wants you to sign in with your Ethereum account:\n", domain)
	fmt.Fprintf(&b, "%s\n", address)
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "%s\n", statement)
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "URI: %s\n", uri)
	fmt.Fprintf(&b, "Version: %s\n", version)
	fmt.Fprintf(&b, "Chain ID: %d\n", chainID)
	fmt.Fprintf(&b, "Nonce: %s\n", nonce)
	fmt.Fprintf(&b, "Issued At: %s", issuedAt)
	return b.String()
}
