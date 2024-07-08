package main

import (
	"database/sql"
	"flag"
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/yourpainkiller/tinyrl/internal/models"

	_ "github.com/lib/pq"
)

type application struct {
	errorLog      *log.Logger
	infoLog       *log.Logger
	links         *models.LinkModel
	users         *models.UserModel
	templateCache map[string]*template.Template
}

func main() {
	infoLog := log.New(os.Stdout, "INFO \t", log.Ldate|log.Ltime)
	errorLog := log.New(os.Stderr, "Error \t", log.Ldate|log.Ltime)

	addr := flag.String("addr", ":4000", "HTTP Network adress")
	connStr := flag.String("connStr", "postgres://postgres:qwe@localhost:5432/test_api?sslmode=disable", "Connection to PostgresQL")
	flag.Parse()

	db, err := openDB(*connStr)
	if err != nil {
		errorLog.Fatal(err)
	}
	defer db.Close()

	templateCache, err := newTemplateCache()
	if err != nil {
		errorLog.Fatal(err)
	}

	app := &application{
		errorLog:      errorLog,
		infoLog:       infoLog,
		links:         &models.LinkModel{DB: db},
		users:         &models.UserModel{DB: db},
		templateCache: templateCache,
	}
	if err = app.users.Deploy(); err != nil {
		errorLog.Fatal(err)
	}
	if err = app.links.Deploy(); err != nil {
		errorLog.Fatal(err)
	}

	srv := &http.Server{
		Addr:     *addr,
		ErrorLog: errorLog,
		Handler:  app.routes(),
	}

	infoLog.Printf("Running server on %s", *addr)
	err = srv.ListenAndServe()
	errorLog.Fatal(err)
}

func openDB(connStr string) (*sql.DB, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}
