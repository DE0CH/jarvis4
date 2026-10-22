// Package routerdb: the router's records as the e2e tests read them, from its database (E2E_DATABASE_URL; the router
// keeps them in Postgres: router/statedb.go), in state.json's old shape: {"sessions": {id: …}, "records": […]}.
package routerdb

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
)

// StateJSON: the router's sessions and records, as one JSON document
func StateJSON() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := pgx.Connect(ctx, os.Getenv("E2E_DATABASE_URL"))
	if err != nil {
		return nil, err
	}
	defer c.Close(ctx)
	sessions := map[string]json.RawMessage{}
	rows, err := c.Query(ctx, "SELECT id, doc FROM sessions")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var doc []byte
		if err := rows.Scan(&id, &doc); err != nil {
			return nil, err
		}
		sessions[id] = doc
	}
	rows.Close()
	records := []json.RawMessage{}
	rows, err = c.Query(ctx, "SELECT doc FROM records ORDER BY ord")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		records = append(records, doc)
	}
	rows.Close()
	return json.Marshal(map[string]any{"sessions": sessions, "records": records})
}
