package statebus

import "context"

type Message struct {
	Value []byte
}

type Consumer interface {
	ReadMessage(ctx context.Context) (Message, error)
	Close() error
}
