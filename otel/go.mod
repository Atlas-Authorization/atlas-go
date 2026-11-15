module github.com/Atlas-Authorization/atlas-go/otel

go 1.26.0

require (
	github.com/Atlas-Authorization/atlas-go v0.27.0
	go.opentelemetry.io/otel v1.24.0
	go.opentelemetry.io/otel/metric v1.24.0
	go.opentelemetry.io/otel/sdk v1.24.0
	go.opentelemetry.io/otel/sdk/metric v1.24.0
	go.opentelemetry.io/otel/trace v1.24.0
)

require (
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

replace github.com/Atlas-Authorization/atlas-go => ../
