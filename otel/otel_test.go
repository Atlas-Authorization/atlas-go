package atlasotel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	atlas "github.com/Atlas-Authorization/atlas-go"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestObserverTracesMetricsAndPropagates(t *testing.T) {
	var gotTraceparent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceparent = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"instance","id":"ins_1"}`))
	}))
	defer srv.Close()

	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	obs := New(WithTracerProvider(tp), WithMeterProvider(mp), WithPropagator(propagation.TraceContext{}))

	c := atlas.New("sk_test", atlas.WithBaseURL(srv.URL), atlas.WithObserver(obs))
	if _, err := c.Instance.Get(context.Background()); err != nil {
		t.Fatalf("call failed: %v", err)
	}

	if gotTraceparent == "" {
		t.Fatalf("traceparent was not sent")
	}
	ended := spans.Ended()
	if len(ended) != 1 || ended[0].Name() != "Atlas GET" {
		t.Fatalf("want one span named %q, got %d", "Atlas GET", len(ended))
	}
	found := map[string]bool{}
	for _, kv := range ended[0].Attributes() {
		found[string(kv.Key)] = true
	}
	for _, k := range []string{"http.request.method", "url.path", "http.response.status_code", "atlas.attempts"} {
		if !found[k] {
			t.Errorf("span is missing attribute %s", k)
		}
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	names := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			names[m.Name] = true
		}
	}
	if !names["atlas.client.requests"] || !names["atlas.client.request.duration"] {
		t.Fatalf("missing instruments, got %v", names)
	}
}
