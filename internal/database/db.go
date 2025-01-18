// internal/database/db.go
package database

import (
	"database/sql"
)

type DB struct {
	*sql.DB
}

type Tx interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

func New() (*DB, error) {
	db, err := Connect()
	if err != nil {
		return nil, err
	}
	return &DB{db}, nil
}

func (db *DB) Begin() (*sql.Tx, error) {
	return db.DB.Begin()
}
