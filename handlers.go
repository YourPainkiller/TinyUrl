package main

import (
	"database/sql"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

var db_connection *sql.DB

func init() {
	connStr := "postgres://postgres:qwe@localhost:5432/test_api?sslmode=disable"
	db_connection, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("OH NIGGA YOUR MOM IS GAY")
	}
}

func Test(w http.ResponseWriter, r *http.Request) {
	db_connection.
}
