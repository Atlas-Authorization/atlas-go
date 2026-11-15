// Package atlasotel adds OpenTelemetry traces and metrics to the Atlas Go SDK.
// It is a nested module (github.com/Atlas-Authorization/atlas-go/otel), so the
// base SDK has no OpenTelemetry dependency; import this package only if you
// want it.
//
//	obs := atlasotel.New() // uses the global tracer and meter providers
//	c := atlas.New("sk_live_...", atlas.WithObserver(obs))
//
// Every API call becomes one client span ("Atlas GET", with the HTTP method,
// path, status and attempt count) and updates two instruments: the
// atlas.client.requests counter and the atlas.client.request.duration
// histogram (seconds), both keyed by method and status. The span's context
// carries W3C trace context (traceparent) on every HTTP attempt, so the call
// joins your trace on the server side.
package atlasotel

import (
	"context"
	"net/http"
	"strconv"
	"time"

	atlas "github.com/Atlas-Authorization/atlas-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// InstrumentationName is the scope name of the tracer and meter.
const InstrumentationName = "github.com/Atlas-Authorization/atlas-go"

// Observer implements atlas.Observer (and atlas.HeaderInjector) with
// OpenTelemetry. Build one with New.
type Observer struct {
	tracer     trace.Tracer
	requests   metric.Int64Counter
	duration   metric.Float64Histogram
	propagator propagation.TextMapPropagator
	now        func() time.Time
}

// Option configures New.
type Option func(*config)

type config struct {
	tp         trace.TracerProvider
	mp         metric.MeterProvider
	propagator propagation.TextMapPropagator
}

// WithTracerProvider uses tp instead of the global tracer provider.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(c *config) { c.tp = tp }
}

// WithMeterProvider uses mp instead of the global meter provider.
func WithMeterProvider(mp metric.MeterProvider) Option {
	return func(c *config) { c.mp = mp }
}

// WithPropagator uses p to inject trace context instead of the global propagator.
func WithPropagator(p propagation.TextMapPropagator) Option {
	return func(c *config) { c.propagator = p }
}

// New builds an Observer. Instrument creation cannot fail with the SDK
// providers; with a misbehaving provider the instrument is left to the
// provider's own no-op handling.
func New(opts ...Option) *Observer {
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}
	if cfg.tp == nil {
		cfg.tp = otel.GetTracerProvider()
	}
	if cfg.mp == nil {
		cfg.mp = otel.GetMeterProvider()
	}
	if cfg.propagator == nil {
		cfg.propagator = otel.GetTextMapPropagator()
	}
	meter := cfg.mp.Meter(InstrumentationName)
	requests, _ := meter.Int64Counter("atlas.client.requests",
		metric.WithDescription("Atlas API calls made by this client."),
		metric.WithUnit("{call}"))
	duration, _ := meter.Float64Histogram("atlas.client.request.duration",
		metric.WithDescription("Duration of Atlas API calls, retries included."),
		metric.WithUnit("s"))
	return &Observer{
		tracer:     cfg.tp.Tracer(InstrumentationName),
		requests:   requests,
		duration:   duration,
		propagator: cfg.propagator,
		now:        time.Now,
	}
}

// StartRequest implements atlas.Observer.
func (o *Observer) StartRequest(ctx context.Context, info atlas.RequestInfo) (context.Context, func(atlas.RequestResult)) {
	start := o.now()
	ctx, span := o.tracer.Start(ctx, "Atlas "+info.Method,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("http.request.method", info.Method),
			attribute.String("url.path", info.Path),
			attribute.String("rpc.system", "atlas"),
		))
	return ctx, func(res atlas.RequestResult) {
		attrs := []attribute.KeyValue{
			attribute.String("http.request.method", info.Method),
			attribute.String("http.response.status_class", statusClass(res.Status)),
		}
		span.SetAttributes(
			attribute.Int("http.response.status_code", res.Status),
			attribute.Int("atlas.attempts", res.Attempts),
		)
		if res.Err != nil {
			span.RecordError(res.Err)
			span.SetStatus(codes.Error, res.Err.Error())
			attrs = append(attrs, attribute.Bool("error", true))
		}
		span.End()
		o.requests.Add(ctx, 1, metric.WithAttributes(attrs...))
		o.duration.Record(ctx, o.now().Sub(start).Seconds(), metric.WithAttributes(attrs...))
	}
}

// InjectHeaders implements atlas.HeaderInjector: it adds traceparent (and
// tracestate) for the span StartRequest opened.
func (o *Observer) InjectHeaders(ctx context.Context, h http.Header) {
	o.propagator.Inject(ctx, propagation.HeaderCarrier(h))
}

func statusClass(status int) string {
	if status < 100 {
		return "none"
	}
	return strconv.Itoa(status/100) + "xx"
}
