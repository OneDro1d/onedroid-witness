module github.com/OneDro1d/onedroid-audit/tools/redact-copy

go 1.23.0

// The store's own rule set, at the version the store pins (onedroid-fleet go.mod). This require line is the one place to
// bump it: change it, then `go mod tidy` and `go mod vendor` (the image builds from vendor/, offline).
require github.com/OneDro1d/onedroid-indie v0.1.0-dev.2.0.20261112093440-ea1bd75f85f9
