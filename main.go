package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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

func tinylinksForm(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, userId, check := checkAuth(r)
		if !check {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
		data := selectAllUserLinks(userId, db)
		tinylinksPage.Execute(w, data)
	}
}

type PageInfo struct {
	UserName string
	SomeInfo string
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Links struct {
	Userlink string `json:"userlink"`
	Tolink   string `json:"tolink"`
	Owner    int    `json:"owner"`
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

func sendJsonAnswer(w http.ResponseWriter, resp map[string]string, code int) bool {
	jsonResponse, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(jsonResponse)
	return true
}

func registerUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var curuser User
		if err := json.NewDecoder(r.Body).Decode(&curuser); err != nil {
			fmt.Println("Error in decoding JSON")
		}

		//fmt.Println(curuser)

		if !validateUsername(curuser.Username) {
			if ans := sendJsonAnswer(w, map[string]string{"status": "Incorrect username"}, 404); !ans {
				fmt.Println("Unable to send JSON answer")
			}
		} else if checkIfUserExists(curuser.Username, db) {
			if ans := sendJsonAnswer(w, map[string]string{"status": "Username already exists"}, 404); !ans {
				fmt.Println("Unable to send JSON answer")
			}
		} else if !validatePassword(curuser.Password) {
			if ans := sendJsonAnswer(w, map[string]string{"status": "Incorrect password"}, 404); !ans {
				fmt.Println("Unable to send JSON answer")
			}
		} else {
			curuser.Password = genHash(curuser.Password)
			insertUser(db, curuser)
			if ans := sendJsonAnswer(w, map[string]string{"status": "Succesfull registration"}, 200); !ans {
				fmt.Println("Unable to send JSON answer")
			}
		}

	}
}

func loginUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var curuser User
		if err := json.NewDecoder(r.Body).Decode(&curuser); err != nil {
			fmt.Println("Error in decoding JSON")
		}

		//log.Printf("username: %v, password: %v \n", curUser.Username, curUser.Password)

		if !checkCorrectPassword(curuser.Username, curuser.Password, db) {
			if ans := sendJsonAnswer(w, map[string]string{"status": "Wrong username or password"}, 400); !ans {
				fmt.Println("Unable to send JSON answer")
			}
		} else {
			userId := strconv.Itoa(getUserId(curuser.Username, db))
			hmacSampleSecret := []byte("secret")
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"username": curuser.Username,
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
			if ans := sendJsonAnswer(w, map[string]string{"status": "Succesfull LogIn"}, 200); !ans {
				fmt.Println("Unable to send JSON answer")
			}
			//http.Redirect(w, r, "/", http.StatusSeeOther)

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
		_, userId, check := checkAuth(r)
		if !check {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		var curlink Links
		if err := json.NewDecoder(r.Body).Decode(&curlink); err != nil {
			fmt.Println("Error in decoding JSON")
		}
		curlink.Owner = userId
		//fmt.Println(curlink)

		if !validatePassword(curlink.Tolink) || curlink.Tolink == "" {
			if ans := sendJsonAnswer(w, map[string]string{"status": "Wrong dest adress"}, 404); !ans {
				fmt.Println("Unable to send JSON answer")
			}
		} else if checkIfLinkExists(curlink.Tolink, db) {
			if ans := sendJsonAnswer(w, map[string]string{"status": "Link already exists"}, 404); !ans {
				fmt.Println("Unable to send JSON answer")
			}
		} else {
			pk := insertLinks(db, curlink)
			fmt.Println(pk)
			//fmt.Println(curlink)
			if ans := sendJsonAnswer(w, map[string]string{"status": "Added link"}, 200); !ans {
				fmt.Println("Unable to send JSON answer")
			}
		}
		//http.Redirect(w, r, "/tinylinks", http.StatusSeeOther)

	}
}

func transfer(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tolink := r.PathValue("link")
		ex := checkIfLinkExists(tolink, db)
		if !ex {
			emptyPage.Execute(w, nil)
		} else {
			userData := selectLink(tolink, db)
			http.Redirect(w, r, userData.Userlink, http.StatusSeeOther)
		}

	}
}

func deleteLink(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tolink := r.PathValue("link")
		ex := checkIfLinkExists(tolink, db)
		_, userId, check := checkAuth(r)
		if !check {
			if ans := sendJsonAnswer(w, map[string]string{"status": "You are not authorized"}, 401); !ans {
				fmt.Println("Unable to send JSON answer")
			}
		} else if !ex {
			if ans := sendJsonAnswer(w, map[string]string{"status": "No such link"}, 404); !ans {
				fmt.Println("Unable to send JSON answer")
			}
		} else if data := selectLink(tolink, db); data.Owner != userId {
			if ans := sendJsonAnswer(w, map[string]string{"status": "No such link"}, 404); !ans {
				fmt.Println("Unable to send JSON answer")
			}
		} else {
			if ans := sendJsonAnswer(w, map[string]string{"status": "Succesfull delete"}, 200); !ans {
				fmt.Println("Unable to send JSON answer")
			}
			check := deleteLinkFromDb(db, tolink)
			fmt.Println(check)
		}

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
	err := db.QueryRow(query, link.Userlink, link.Tolink, link.Owner).Scan(&pk)
	if err != nil {
		log.Fatal("Error in inserting link\n", err)
	}
	return pk
}

func insertUser(db *sql.DB, user User) int {
	query := `INSERT INTO users (username, password)
		VALUES($1, $2) RETURNING id`

	var pk int
	err := db.QueryRow(query, user.Username, user.Password).Scan(&pk)
	if err != nil {
		log.Fatal("Error in inserting user\n", err)
	}
	return pk
}

func deleteLinkFromDb(db *sql.DB, tolink string) bool {
	query := `DELETE FROM links 
		WHERE tolink = $1`

	_, err := db.Exec(query, tolink)
	if err != nil {
		log.Fatal("Error in deleting link\n", err)
	}
	return true
}

func selectLink(to string, db *sql.DB) Links {
	query := `SELECT userlink, owner FROM links WHERE tolink = $1`
	var userlink string
	var owner int
	err := db.QueryRow(query, to).Scan(&userlink, &owner)
	if err != nil {
		log.Fatal("Error in selecting link\n", err)
	}
	data := Links{Userlink: userlink, Tolink: to, Owner: owner}
	return data
}

func selectAllUserLinks(userId int, db *sql.DB) []Links {
	data := []Links{}
	rows, err := db.Query("SELECT userlink, tolink FROM links WHERE owner = $1 ORDER BY id ASC", userId)
	if err != nil {
		log.Fatal("Error in selecting all links\n", err)
	}

	defer rows.Close()
	var userlink string
	var tolink string

	for rows.Next() {
		err := rows.Scan(&userlink, &tolink)
		if err != nil {
			log.Fatal("Error in parsing links\n", err)
		}

		data = append(data, Links{Userlink: userlink, Tolink: tolink, Owner: userId})
	}
	//fmt.Println(data)
	return data
}

func main() {
	connStr := "postgres://postgres:qwe@localhost:5432/test_api?sslmode=disable"
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

	mux.Handle("/static/*", http.StripPrefix("/static/", fs))

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
	mux.HandleFunc("GET /tinylinks", tinylinksForm(db))
	mux.HandleFunc("POST /tinylinks", shortLink(db))
	mux.HandleFunc("GET /logout", logoutUser)
	mux.HandleFunc("GET /s/{link}", transfer(db))
	mux.HandleFunc("DELETE /s/{link}", deleteLink(db))

	if err := http.ListenAndServe("localhost:8080", mux); err != nil {
		log.Fatal("Error in listening and serving\n", err)
	}

}
