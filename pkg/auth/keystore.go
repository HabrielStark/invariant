package auth

import "context"

// KeyRecord holds agent public key metadata.
type KeyRecord struct {
	Kid       string
	Signer    string
	PublicKey []byte
	Status    string // active|revoked
}

type KeyStore interface {
	GetKey(ctx context.Context, kid string) (*KeyRecord, error)
}
