package statebus

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

type KafkaConsumer struct {
	reader kafkaReader
}

type kafkaReader interface {
	ReadMessage(ctx context.Context) (kafka.Message, error)
	Close() error
}

type KafkaConfig struct {
	Brokers []string
	Topic   string
	GroupID string
}

func NewKafkaConsumer(cfg KafkaConfig) (*KafkaConsumer, error) {
	brokers := make([]string, 0, len(cfg.Brokers))
	for _, b := range cfg.Brokers {
		trimmed := strings.TrimSpace(b)
		if trimmed != "" {
			brokers = append(brokers, trimmed)
		}
	}
	if len(brokers) == 0 {
		return nil, fmt.Errorf("kafka brokers required")
	}
	if strings.TrimSpace(cfg.Topic) == "" {
		return nil, fmt.Errorf("kafka topic required")
	}
	if strings.TrimSpace(cfg.GroupID) == "" {
		return nil, fmt.Errorf("kafka group id required")
	}
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Topic:          cfg.Topic,
		GroupID:        cfg.GroupID,
		MinBytes:       1,
		MaxBytes:       10e6,
		CommitInterval: time.Second,
		MaxWait:        500 * time.Millisecond,
	})
	return &KafkaConsumer{reader: r}, nil
}

func (c *KafkaConsumer) ReadMessage(ctx context.Context) (Message, error) {
	if c == nil || c.reader == nil {
		return Message{}, fmt.Errorf("kafka consumer not initialized")
	}
	msg, err := c.reader.ReadMessage(ctx)
	if err != nil {
		return Message{}, err
	}
	return Message{Value: msg.Value}, nil
}

func (c *KafkaConsumer) Close() error {
	if c == nil || c.reader == nil {
		return nil
	}
	return c.reader.Close()
}
