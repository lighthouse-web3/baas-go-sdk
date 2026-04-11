package backup

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrdecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// WalletAdapter abstracts Ethereum wallet operations.
type WalletAdapter struct {
	Address     string
	SignMessage func(message string) (string, error)
}

// WalletFromPrivateKey creates a WalletAdapter from a hex-encoded secp256k1 private key.
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

// WalletFromSigner creates a WalletAdapter from an address and external sign function.
func WalletFromSigner(address string, signFn func(string) (string, error)) *WalletAdapter {
	return &WalletAdapter{
		Address:     address,
		SignMessage: signFn,
	}
}

// Authenticate performs the full SIWE authentication flow:
//  1. Request nonce from server
//  2. Build EIP-4361 message with the nonce
//  3. Sign message with wallet
//  4. Send message + signature to server → receive JWT
//
// The JWT is stored on the HttpClient for all subsequent calls.
func Authenticate(http *HttpClient, wallet *WalletAdapter) (string, error) {
	nonce, err := http.RequestNonce(strings.ToLower(wallet.Address))
	if err != nil {
		return "", fmt.Errorf("request nonce: %w", err)
	}

	siweMsg := buildSIWEMessage(
		nonce.Domain,
		wallet.Address,
		"Sign in to Backup Service",
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

	authResp, err := http.Verify(siweMsg, signature)
	if err != nil {
		return "", fmt.Errorf("verify: %w", err)
	}

	http.SetToken(authResp.Token)
	return authResp.Token, nil
}

// ── Internal helpers ────────────────────────────────────────────────────────

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
	hash := keccak256(uncompressed[1:]) // skip 0x04 prefix
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

	// dcrd SignCompact returns 65 bytes:
	//   [0]     = recovery flag + 27
	//   [1:33]  = R (big-endian, zero-padded)
	//   [33:65] = S (big-endian, zero-padded)
	sig := dcrdecdsa.SignCompact(privKey, hash, false)

	// Ethereum format: R || S || V
	ethSig := make([]byte, 65)
	copy(ethSig[0:32], sig[1:33])  // R
	copy(ethSig[32:64], sig[33:65]) // S
	ethSig[64] = sig[0]             // V (27 or 28)

	return "0x" + hex.EncodeToString(ethSig), nil
}

// buildSIWEMessage constructs an EIP-4361 compliant message.
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
