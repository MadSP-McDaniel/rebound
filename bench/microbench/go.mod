module github.com/MadSP-McDaniel/rebound-bench

go 1.24.0

toolchain go1.24.5

require (
	github.com/MadSP-McDaniel/librebound v0.0.0
	golang.org/x/mod v0.28.0
	k8s.io/klog/v2 v2.130.1
)

require (
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgraph-io/badger/v4 v4.8.0 // indirect
	github.com/dgraph-io/ristretto/v2 v2.2.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/flatbuffers v25.2.10+incompatible // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/transparency-dev/formats v0.0.0-20250421220931-bb8ad4d07c26 // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	github.com/transparency-dev/tessera v1.0.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/exp v0.0.0-20240325151524-a685a6edb6d8 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
)

replace github.com/MadSP-McDaniel/librebound => ../../librebound

replace github.com/transparency-dev/tessera => ../../tessera
