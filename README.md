# Jarvis 4

A second, independent Jarvis built on the secrets-controller design; runs side by side with Jarvis 1,
which stays exactly as it is. Plan and status: [docs/PLAN.md](docs/PLAN.md).

- `core/` — the secrets controller (Go): signed answers, in-memory state, the primitives; `go test ./...`
