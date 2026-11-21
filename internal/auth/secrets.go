package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrobson/hacknation-agh/internal/config"
	"github.com/chrobson/hacknation-agh/internal/store"
)

// ErrNoSecretKey is returned when ASI_SECRET_KEY is not configured.
var ErrNoSecretKey = errors.New("ASI_SECRET_KEY is not set")

// sealVersion prefixes ciphertexts so the format can evolve.
const sealVersion byte = 1

// Sealer encrypts application secrets with AES-256-GCM. The secret name is
// bound as additional data, so a ciphertext cannot be moved to another name.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a Sealer from a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) == 0 {
		return nil, ErrNoSecretKey
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secret key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext: version || nonce || ciphertext+tag.
func (s *Sealer) Seal(name string, plaintext []byte) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	_, _ = rand.Read(nonce)
	out := append([]byte{sealVersion}, nonce...)
	return s.aead.Seal(out, nonce, plaintext, []byte(name))
}

// Open decrypts a value produced by Seal for the same name.
func (s *Sealer) Open(name string, sealed []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(sealed) < 1+ns+s.aead.Overhead() || sealed[0] != sealVersion {
		return nil, errors.New("invalid sealed secret")
	}
	pt, err := s.aead.Open(nil, sealed[1:1+ns], sealed[1+ns:], []byte(name))
	if err != nil {
		return nil, fmt.Errorf("decrypt secret %q: %w", name, err)
	}
	return pt, nil
}

// PutSecret encrypts value with cfg.SecretKey and stores it in secrets.
func PutSecret(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, name, value string) error {
	s, err := NewSealer(cfg.SecretKey)
	if err != nil {
		return err
	}
	return store.PutSecretEnc(ctx, pool, name, s.Seal(name, []byte(value)))
}

// GetSecret loads and decrypts a secret. Returns pgx.ErrNoRows when absent.
func GetSecret(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, name string) (string, error) {
	s, err := NewSealer(cfg.SecretKey)
	if err != nil {
		return "", err
	}
	enc, err := store.GetSecretEnc(ctx, pool, name)
	if err != nil {
		return "", err
	}
	pt, err := s.Open(name, enc)
	return string(pt), err
}
