package telemetry

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/semconv/v1.25.0"
)

// Init configures global OpenTelemetry tracing.
func Init(ctx context.Context, serviceName string) (func(context.Context) error, error) {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		serviceName = "axiomos"
	}
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	headers := parseHeaders(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"))
	timeout := time.Second * time.Duration(envInt("OTEL_EXPORTER_OTLP_TIMEOUT_SEC", 5))
	insecure := os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == "true"
	required := os.Getenv("OTEL_REQUIRED") == "true"
	sampler := parseSampler(os.Getenv("OTEL_TRACES_SAMPLER"), os.Getenv("OTEL_TRACES_SAMPLER_ARG"))

	res, _ := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(serviceName),
	))
	if endpoint == "" {
		tp := trace.NewTracerProvider(trace.WithResource(res), trace.WithSampler(sampler))
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.TraceContext{})
		return tp.Shutdown, nil
	}
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithTimeout(timeout),
	}
	if insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(headers))
	}
	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		if required {
			return nil, err
		}
		log.Printf("otel exporter disabled: %v", err)
		tp := trace.NewTracerProvider(trace.WithResource(res), trace.WithSampler(sampler))
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.TraceContext{})
		return tp.Shutdown, nil
	}
	tp := trace.NewTracerProvider(
		trace.WithResource(res),
		trace.WithSampler(sampler),
		trace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return tp.Shutdown, nil
}

func parseSampler(name, arg string) trace.Sampler {
	name = strings.ToLower(strings.TrimSpace(name))
	arg = strings.TrimSpace(arg)
	ratio := 1.0
	if arg != "" {
		if val, err := strconv.ParseFloat(arg, 64); err == nil {
			if val < 0 {
				val = 0
			}
			if val > 1 {
				val = 1
			}
			ratio = val
		}
	}
	switch name {
	case "always_on":
		return trace.AlwaysSample()
	case "always_off":
		return trace.NeverSample()
	case "traceidratio":
		return trace.TraceIDRatioBased(ratio)
	case "parentbased_traceidratio", "parentbased_traceid_ratio", "parentbased":
		return trace.ParentBased(trace.TraceIDRatioBased(ratio))
	default:
		return trace.ParentBased(trace.TraceIDRatioBased(ratio))
	}
}

// HTTPMiddleware instruments inbound HTTP handlers.
func HTTPMiddleware(serviceName string) func(http.Handler) http.Handler {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		serviceName = "axiomos"
	}
	return otelhttp.NewMiddleware(serviceName)
}

// InstrumentClient wraps an HTTP client with OTel transport.
func InstrumentClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = otelhttp.NewTransport(base)
	return client
}

func parseHeaders(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := map[string]string{}
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if k != "" {
			out[k] = v
		}
	}
	return out
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}
