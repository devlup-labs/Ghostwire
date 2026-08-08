package database

import (
	"context"
	"database/sql"

	_ "embed"

	_ "modernc.org/sqlite"

	"github.com/devlup-labs/Ghostwire/coordination-server/database/sqlc_db"
)

var ctx = context.Background()
var DbQueries *sqlc_db.Queries

//go:embed schema.sql
var ddl string

func InitializeDatabase(filename string) error {
	db, err := sql.Open("sqlite", filename)
	if err != nil {
		return err
	}

	// create tables
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return err
	}

	DbQueries = sqlc_db.New(db)
	return nil
}
