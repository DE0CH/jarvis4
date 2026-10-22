module github.com/DE0CH/jarvis4/e2e

go 1.25.1

require (
	github.com/DE0CH/jarvis4/kernel v0.0.0
	github.com/jackc/pgx/v5 v5.7.6
)

require (
	filippo.io/nistec v0.0.4 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.24.0 // indirect
)

replace github.com/DE0CH/jarvis4/kernel => ../kernel
