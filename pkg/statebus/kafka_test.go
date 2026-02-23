package statebus

import (
	"context"
	"errors"
	"testing"

	"github.com/segmentio/kafka-go"
)

func TestNewKafkaConsumerValidation(t *testing.T) {
	t.Parallel()

	_, err := NewKafkaConsumer(KafkaConfig{Topic: "events", GroupID: "g1"})
	if err == nil {
		t.Fatal("expected error when brokers are missing")
	}

	_, err = NewKafkaConsumer(KafkaConfig{Brokers: []string{"127.0.0.1:9092"}, GroupID: "g1"})
	if err == nil {
		t.Fatal("expected error when topic is missing")
	}

	_, err = NewKafkaConsumer(KafkaConfig{Brokers: []string{"127.0.0.1:9092"}, Topic: "events"})
	if err == nil {
		t.Fatal("expected error when group id is missing")
	}
}

func TestNewKafkaConsumerTrimsBrokerList(t *testing.T) {
	t.Parallel()

	consumer, err := NewKafkaConsumer(KafkaConfig{
		Brokers: []string{" ", "127.0.0.1:9092", "\t"},
		Topic:   "events",
		GroupID: "g1",
	})
	if err != nil {
		t.Fatalf("expected valid consumer config, got error: %v", err)
	}
	if consumer == nil {
		t.Fatal("expected consumer")
	}
	if err := consumer.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func TestKafkaConsumerCloseAndReadGuard(t *testing.T) {
	t.Parallel()

	var nilConsumer *KafkaConsumer
	if err := nilConsumer.Close(); err != nil {
		t.Fatalf("expected nil close to be no-op, got: %v", err)
	}
	if _, err := nilConsumer.ReadMessage(context.Background()); err == nil {
		t.Fatal("expected read error for nil consumer")
	}

	consumer := &KafkaConsumer{}
	if _, err := consumer.ReadMessage(context.Background()); err == nil {
		t.Fatal("expected read error for uninitialized reader")
	}
}

type fakeKafkaReader struct {
	msg      kafka.Message
	err      error
	readHits int
}

func (f *fakeKafkaReader) ReadMessage(ctx context.Context) (kafka.Message, error) {
	f.readHits++
	if f.err != nil {
		return kafka.Message{}, f.err
	}
	return f.msg, nil
}

func (f *fakeKafkaReader) Close() error {
	return nil
}

func TestKafkaConsumerReadMessageBranches(t *testing.T) {
	t.Run("reader_error", func(t *testing.T) {
		consumer := &KafkaConsumer{
			reader: &fakeKafkaReader{err: errors.New("read failed")},
		}
		if _, err := consumer.ReadMessage(context.Background()); err == nil {
			t.Fatal("expected reader error")
		}
	})

	t.Run("reader_success", func(t *testing.T) {
		consumer := &KafkaConsumer{
			reader: &fakeKafkaReader{msg: kafka.Message{Value: []byte(`{"k":"v"}`)}},
		}
		msg, err := consumer.ReadMessage(context.Background())
		if err != nil {
			t.Fatalf("unexpected read error: %v", err)
		}
		if string(msg.Value) != `{"k":"v"}` {
			t.Fatalf("unexpected message value: %s", string(msg.Value))
		}
	})
}
