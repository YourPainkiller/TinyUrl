package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/golang-jwt/jwt"
)

func (app *application) serverError(w http.ResponseWriter, err error) {
	trace := fmt.Sprintf("%s\n%s", err.Error(), debug.Stack())
	app.errorLog.Output(2, trace)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func (app *application) clientError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

func (app *application) notFound(w http.ResponseWriter) {
	app.clientError(w, http.StatusNotFound)
}

func (app *application) render(w http.ResponseWriter, status int, page string, data *templateData) {
	ts, ok := app.templateCache[page]
	if !ok {
		err := fmt.Errorf("the template %s does not exists", page)
		app.serverError(w, err)
	}

	buf := new(bytes.Buffer)
	err := ts.ExecuteTemplate(buf, "base", data)
	if err != nil {
		app.serverError(w, err)
	}
	w.WriteHeader(status)
	buf.WriteTo(w)

}

func parseCookie(r *http.Request) (bool, string, error) {
	cookie, err := r.Cookie("jwtToken")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return false, "", nil
		}
		return false, "", err

	}
	if cookie.Value == "" {
		return false, "", nil
	}

	hmacSampleSecret := []byte("secret")
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return hmacSampleSecret, nil
	})
	if err != nil {
		return false, "", err
	}
	if !token.Valid {
		return false, "", nil
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		username, _ := claims["username"].(string)
		return true, username, nil
	}
	return false, "", nil

}

func genHash(str string) string {
	h := sha256.New()
	h.Write([]byte(str))
	//TODO: Передавать секрет вместо nil
	fh := h.Sum(nil)
	temp := hex.EncodeToString(fh)
	return string(temp)
}

func genToken(username string) (string, error) {
	hmacSampleSecret := []byte("secret")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
	})
	tokenString, err := token.SignedString(hmacSampleSecret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func sendJson(w http.ResponseWriter, data map[string]string, code int) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	jsonResponse, err := json.Marshal(data)
	if err != nil {
		return err
	}
	w.Write(jsonResponse)
	return nil
}
