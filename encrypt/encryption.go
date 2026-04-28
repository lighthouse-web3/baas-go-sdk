package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	sdktypes "github.com/lighthouse-web3/baas-go-sdk/types"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	keySize   = 32
	nonceSize = 12

	hkdfLabelData = "lighthouse/enc/v1/data"
	hkdfLabelTree = "lighthouse/enc/v1/tree"

	encryptionScheme       = "lighthouse-v1"
	encryptionDekAlgorithm = "aes-256-gcm"
)

// DefaultArgon2Params provides default Argon2id parameters for keyfile protection.
var DefaultArgon2Params = Argon2Params{
	Time:    3,
	Memory:  64 * 1024,
	Threads: 4,
}

// Argon2Params holds the tunable Argon2id cost parameters.
type Argon2Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	Salt    string `json:"salt"`
}

type keyfileTMK struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// KeyfileData is the JSON structure persisted as the passphrase-protected keyfile.
type KeyfileData struct {
	Version   int          `json:"version"`
	Algorithm string       `json:"algorithm"`
	Params    Argon2Params `json:"params"`
	TMK       keyfileTMK   `json:"tmk"`
}

// GenerateKeyfile creates a new keyfile and returns the plaintext TMK.
func GenerateKeyfile(path, passphrase string, params *Argon2Params) ([]byte, error) {
	if params == nil {
		params = &DefaultArgon2Params
	}

	tmk := make([]byte, keySize)
	if _, err := rand.Read(tmk); err != nil {
		return nil, fmt.Errorf("generate TMK: %w", err)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	kek := argon2.IDKey([]byte(passphrase), salt, params.Time, params.Memory, params.Threads, keySize)
	sealed, nonce, err := aesGCMSeal(kek, tmk)
	if err != nil {
		return nil, fmt.Errorf("seal TMK: %w", err)
	}

	kf := KeyfileData{
		Version:   1,
		Algorithm: "argon2id",
		Params: Argon2Params{
			Time:    params.Time,
			Memory:  params.Memory,
			Threads: params.Threads,
			Salt:    base64.StdEncoding.EncodeToString(salt),
		},
		TMK: keyfileTMK{
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(sealed),
		},
	}

	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, fmt.Errorf("write keyfile: %w", err)
	}
	return tmk, nil
}

// OpenKeyfile loads and decrypts the TMK from an existing keyfile.
func OpenKeyfile(path, passphrase string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keyfile: %w", err)
	}
	var kf KeyfileData
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("parse keyfile: %w", err)
	}
	if kf.Version != 1 {
		return nil, fmt.Errorf("unsupported keyfile version %d", kf.Version)
	}

	salt, err := base64.StdEncoding.DecodeString(kf.Params.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(kf.TMK.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(kf.TMK.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	kek := argon2.IDKey([]byte(passphrase), salt, kf.Params.Time, kf.Params.Memory, kf.Params.Threads, keySize)
	tmk, err := aesGCMOpen(kek, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt TMK (wrong passphrase?): %w", err)
	}
	return tmk, nil
}

func GenerateDEK() ([]byte, error) {
	dek := make([]byte, keySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	return dek, nil
}

func WrapDEK(tmk, dek []byte) (string, error) {
	sealed, nonce, err := aesGCMSeal(tmk, dek)
	if err != nil {
		return "", err
	}
	blob := append(nonce, sealed...)
	return base64.StdEncoding.EncodeToString(blob), nil
}

func UnwrapDEK(tmk []byte, wrappedB64 string) ([]byte, error) {
	blob, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		return nil, fmt.Errorf("decode wrappedDek: %w", err)
	}
	if len(blob) < nonceSize+1 {
		return nil, fmt.Errorf("wrappedDek too short")
	}
	return aesGCMOpen(tmk, blob[:nonceSize], blob[nonceSize:])
}

func RewrapDEK(oldTMK, newTMK []byte, wrappedB64 string) (string, error) {
	dek, err := UnwrapDEK(oldTMK, wrappedB64)
	if err != nil {
		return "", fmt.Errorf("unwrap with old TMK: %w", err)
	}
	return WrapDEK(newTMK, dek)
}

func RewrapDEKIdempotent(oldTMK, newTMK []byte, wrappedB64 string) (string, bool, error) {
	dek, err := UnwrapDEK(oldTMK, wrappedB64)
	if err == nil {
		rewrapped, werr := WrapDEK(newTMK, dek)
		if werr != nil {
			return "", false, werr
		}
		return rewrapped, true, nil
	}
	if _, err2 := UnwrapDEK(newTMK, wrappedB64); err2 == nil {
		return wrappedB64, false, nil
	}
	return "", false, fmt.Errorf("unwrap failed with both old and new TMK: %w", err)
}

var hkdfSalt = make([]byte, 32)

func DeriveObjectKey(dek []byte, label, plaintextHashHex string) ([]byte, error) {
	hashBytes, err := hex.DecodeString(plaintextHashHex)
	if err != nil {
		return nil, fmt.Errorf("decode hash hex: %w", err)
	}
	info := append([]byte(label), hashBytes...)
	r := hkdf.New(sha256.New, dek, hkdfSalt, info)
	key := make([]byte, keySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return key, nil
}

func DeriveDataKey(dek []byte, plaintextHashHex string) ([]byte, error) {
	return DeriveObjectKey(dek, hkdfLabelData, plaintextHashHex)
}

func DeriveTreeKey(dek []byte, plaintextHashHex string) ([]byte, error) {
	return DeriveObjectKey(dek, hkdfLabelTree, plaintextHashHex)
}

func EncryptObject(key, plaintext []byte) ([]byte, error) {
	sealed, nonce, err := aesGCMSeal(key, plaintext)
	if err != nil {
		return nil, err
	}
	return append(nonce, sealed...), nil
}

func DecryptObject(key, blob []byte) ([]byte, error) {
	if len(blob) < nonceSize+1 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return aesGCMOpen(key, blob[:nonceSize], blob[nonceSize:])
}

func aesGCMSeal(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func aesGCMOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// LoadTMK resolves the TMK from EncryptionOptions.
func LoadTMK(opts *sdktypes.EncryptionOptions) ([]byte, error) {
	passphrase := opts.Passphrase
	if passphrase == "" && opts.PassphraseFunc != nil {
		var err error
		passphrase, err = opts.PassphraseFunc()
		if err != nil {
			return nil, fmt.Errorf("passphrase callback: %w", err)
		}
	}
	if passphrase == "" {
		return nil, fmt.Errorf("encryption passphrase is required")
	}
	return OpenKeyfile(opts.KeyfilePath, passphrase)
}

// NewEncryptionMeta returns the EncryptionMeta stored with snapshots.
func NewEncryptionMeta() *sdktypes.EncryptionMeta {
	return &sdktypes.EncryptionMeta{
		Scheme:         encryptionScheme,
		DekWrappedWith: encryptionDekAlgorithm,
	}
}
