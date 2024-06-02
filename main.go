package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

var mainPage = template.Must(template.ParseFiles("html/index.html"))
var registerPage = template.Must(template.ParseFiles("html/register.html"))
var loginPage = template.Must(template.ParseFiles("html/login.html"))
var tinylinksPage = template.Must(template.ParseFiles("html/tinylinks.html"))
var emptyPage = template.Must(template.ParseFiles("html/empty.html"))

func loginForm(w http.ResponseWriter, r *http.Request) {
	loginPage.Execute(w, nil)
}

func registerForm(w http.ResponseWriter, r *http.Request) {
	registerPage.Execute(w, nil)
}

func tinylinksForm(w http.ResponseWriter, r *http.Request) {
	username, _, check := checkAuth(r)
	if !check {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	tinylinksPage.Execute(w, PageInfo{UserName: username})
}

type PageInfo struct {
	UserName string
	SomeInfo string
}

type User struct {
	username string
	password string
}

type Links struct {
	userlink string
	tolink   string
	owner    int
}

func validatePassword(password string) bool {
	whiteList := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
	if len(password) == 0 {
		return false
	}

	for _, char := range password {
		if !strings.ContainsRune(whiteList, char) {
			fmt.Printf("Character '%c' is not in the whitelist\n", char)
			return false
		}
	}
	return true
}

func validateUsername(username string) bool {
	whiteList := "abcdefghijklmnopqrstuvwxyz1234567890_"
	if len(username) == 0 {
		return false
	}

	for _, char := range username {
		if !strings.ContainsRune(whiteList, char) {
			fmt.Printf("Character '%c' is not in the whitelist\n", char)
			return false
			// Handle the case where a character is not in the whitelist
		}
	}
	return true
}

func checkCorrectPassword(username, password string, db *sql.DB) bool {
	if !checkIfUserExists(username, db) {
		return false
	}

	var pasInBase string
	query := `SELECT password FROM users WHERE username = $1`

	err := db.QueryRow(query, username).Scan(&pasInBase)
	if err != nil {
		log.Fatal("Error in SQL query in checking password\n", err)
	}

	if pasInBase != genHash(password) {
		return false
	} else {
		return true
	}
}

func checkAuth(r *http.Request) (username string, userId int, check bool) {
	cookie, err := r.Cookie("jwtToken")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "No cookie", 0, false
		} else {
			log.Println("Probably server error\n", err)
			return "Server error", 0, false
		}
	}
	if cookie.Value == "" {
		return "empty cookie", 0, false
	}

	hmacSampleSecret := []byte("secret")
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSampleSecret, nil
	})
	if err != nil {
		log.Println("Error in reading JWT\n", err)
	}

	if !token.Valid {
		return "Token not valid", 0, false
	} else {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			username, ok := claims["username"].(string)
			if !ok {
				return "Cant convert to string", 0, false
			} else {
				userIdString, ok := claims["userId"].(string)
				if !ok {
					return "Cant convert to string", 0, false
				}
				userId, err := strconv.Atoi(userIdString)
				if err != nil {
					return "Cant convert to int", 0, false
				}
				return username, userId, true
			}
		} else {
			return "Wrong token payload", 0, false
		}
	}
	// return cookie.Value, true
}

func checkIfUserExists(username string, db *sql.DB) bool {
	var check bool
	query := `SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)`
	err := db.QueryRow(query, username).Scan(&check)
	if err != nil {
		log.Fatal("Error in checking if Users Exists\n", err)
	}
	return check
}

func checkIfLinkExists(tolink string, db *sql.DB) bool {
	var check bool
	query := `SELECT EXISTS (SELECT 1 FROM links WHERE tolink = $1)`
	err := db.QueryRow(query, tolink).Scan(&check)
	if err != nil {
		log.Fatal("Error in checking if Link exists\n", err)
	}
	return check
}

func registerUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		curUser := User{username: r.Form.Get("username"), password: r.Form.Get("password")}
		log.Printf("username: %v, password: %v \n", curUser.username, curUser.password)
		cookie1 := &http.Cookie{Name: "sampleTest", Value: "sample", Path: "/"}
		http.SetCookie(w, cookie1)
		if !validateUsername(curUser.username) {
			registerPage.Execute(w, PageInfo{SomeInfo: "Wrong Username"})
		} else if checkIfUserExists(curUser.username, db) {
			registerPage.Execute(w, PageInfo{SomeInfo: "Username already exists"})
		} else if !validatePassword(curUser.password) {
			fmt.Println(curUser.password)
			registerPage.Execute(w, PageInfo{SomeInfo: "Wrong Password"})
		} else {
			registerPage.Execute(w, PageInfo{SomeInfo: "Succesfull registration"})
			curUser.password = genHash(curUser.password)
			insertUser(db, curUser)
		}

	}
}

func loginUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// заменить на работу с Json и парсить соответсвенно Json а не ебучую форму, чтобы это можно было тестить через curl или Insomnia
		r.ParseForm()
		curUser := User{username: r.Form.Get("username"), password: r.Form.Get("password")}
		log.Printf("username: %v, password: %v \n", curUser.username, curUser.password)
		if !checkCorrectPassword(curUser.username, curUser.password, db) {
			loginPage.Execute(w, PageInfo{SomeInfo: "Wrong username or password"})
		} else {
			userId := strconv.Itoa(getUserId(curUser.username, db))
			hmacSampleSecret := []byte("secret")
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"username": curUser.username,
				"userId":   userId,
			})

			tokenString, err := token.SignedString(hmacSampleSecret)
			if err != nil {
				log.Println("Error in signing JWT\n", err)
			}

			cookie := http.Cookie{
				Name:   "jwtToken",
				Value:  tokenString,
				Path:   "/",
				MaxAge: 3600,
			}
			http.SetCookie(w, &cookie)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}

	}
}

func logoutUser(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:   "jwtToken",
		Value:  "",
		Path:   "/",
		MaxAge: 0,
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getUserId(username string, db *sql.DB) (userId int) {
	query := `SELECT id FROM users WHERE username = $1`
	err := db.QueryRow(query, username).Scan(&userId)
	if err != nil {
		log.Fatal("Error in geting userId\n", err)
	}
	return userId
}

func shortLink(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		_, userId, check := checkAuth(r)
		if !check {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
		tolink := r.Form.Get("to")
		if !validatePassword(tolink) {
			tinylinksPage.Execute(w, PageInfo{SomeInfo: "Wrong dest adress"})
		} else if checkIfLinkExists(tolink, db) {
			tinylinksPage.Execute(w, PageInfo{SomeInfo: "Link already exists"})
		}
		curLink := Links{r.Form.Get("userlink"), tolink, userId}
		pk := insertLinks(db, curLink)
		fmt.Println(pk)
		fmt.Println(curLink)
		http.Redirect(w, r, "/tinylinks", http.StatusSeeOther)

	}
}

func transfer(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tolink := r.PathValue("link")
		if !checkIfLinkExists(tolink, db) {
			emptyPage.Execute(w, nil)
		}
		from := selectLink(tolink, db)
		http.Redirect(w, r, from, http.StatusSeeOther)

	}
}

func genHash(str string) string {
	h := sha256.New()
	h.Write([]byte(str))
	//TODO: Передавать секрет вместо nil
	fh := h.Sum(nil)
	temp := hex.EncodeToString(fh)
	return string(temp)
}

func createUserTable(db *sql.DB) {
	query := `CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(100) NOT NULL,
		password VARCHAR(100) NOT NULL
	)`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatal("Error in creating users table\n", err)
	}
	fmt.Println("User table created")
}

func createLinkTable(db *sql.DB) {
	query := `CREATE TABLE IF NOT EXISTS links (
		id SERIAL PRIMARY KEY,
		userlink VARCHAR(100) NOT NULL,
		tolink VARCHAR(100) NOT NULL,
		owner INT REFERENCES users(id)
	)`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatal("Error in creating links table\n", err)
	}
	fmt.Println("Links table created")
}

func insertLinks(db *sql.DB, link Links) int {
	query := `INSERT INTO links (userlink, tolink, owner)
		VALUES($1, $2, $3) RETURNING id`

	var pk int
	err := db.QueryRow(query, link.userlink, link.tolink, link.owner).Scan(&pk)
	if err != nil {
		log.Fatal("Error in inserting link\n", err)
	}
	return pk
}

func insertUser(db *sql.DB, user User) int {
	query := `INSERT INTO users (username, password)
		VALUES($1, $2) RETURNING id`

	var pk int
	err := db.QueryRow(query, user.username, user.password).Scan(&pk)
	if err != nil {
		log.Fatal("Error in inserting user\n", err)
	}
	return pk
}

func selectLink(to string, db *sql.DB) string {
	var income string
	query := `SELECT userlink FROM links WHERE tolink = $1`
	err := db.QueryRow(query, to).Scan(&income)
	if err != nil {
		log.Fatal("Error in selecting link\n", err)
	}
	return income
}

func main() {
	connStr := "postgres://postgres:secret@localhost:5432/test_api?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error in connecting to PSQL\n", err)
	}

	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatal("Error in pinging DB\n", err)
	}
	createUserTable(db)
	createLinkTable(db)

	fs := http.FileServer(http.Dir("static"))

	mux := http.NewServeMux()

	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		username, _, check := checkAuth(r)
		if check {
			mainPage.Execute(w, PageInfo{UserName: username})
		} else {
			mainPage.Execute(w, PageInfo{UserName: "ANON"})
		}
	})

	mux.HandleFunc("GET /register", registerForm)
	mux.HandleFunc("POST /register", registerUser(db))
	mux.HandleFunc("GET /login", loginForm)
	mux.HandleFunc("POST /login", loginUser(db))
	mux.HandleFunc("GET /tinylinks", tinylinksForm)
	mux.HandleFunc("POST /tinylinks", shortLink(db))
	mux.HandleFunc("GET /logout", logoutUser)
	mux.HandleFunc("GET /s/{link}", transfer(db))

	if err := http.ListenAndServe("localhost:8080", mux); err != nil {
		log.Fatal("Error in listening and serving\n", err)
	}

}
