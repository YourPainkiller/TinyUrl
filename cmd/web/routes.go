package main

import (
	"net/http"
)

func (app *application) routes() *http.ServeMux {
	mux := http.NewServeMux()
	fileServer := http.FileServer(http.Dir("./ui/static/"))
	mux.Handle("/static/", http.StripPrefix("/static", fileServer))
	mux.HandleFunc("/", app.home)
	mux.HandleFunc("GET /user/register", app.registerUserForm)
	mux.HandleFunc("POST /user/register", app.registerUser)
	mux.HandleFunc("GET /user/login", app.loginUserForm)
	mux.HandleFunc("POST /user/login", app.loginUser)
	mux.HandleFunc("GET /user/tinylinks", app.tinylinksForm)
	mux.HandleFunc("POST /user/tinylinks", app.tinylinks)
	mux.HandleFunc("GET /s/{link}", app.transfer)
	mux.HandleFunc("DELETE /s/{link}", app.deleteTinyLink)
	mux.HandleFunc("GET /user/logout", app.logout)
	return mux
}
