package main

import (
	"encoding/json"
	"net/http"

	"github.com/yourpainkiller/tinyrl/internal/validator"
)

type UserData struct {
	Username            string `json:"username"`
	Password            string `json:"password"`
	validator.Validator `json:"-"`
}

type LinksData struct {
	Userlink            string `json:"userlink"`
	Tolink              string `json:"tolink"`
	validator.Validator `json:"-"`
}

func (app *application) home(w http.ResponseWriter, r *http.Request) {
	app.render(w, http.StatusAccepted, "home.tmpl.html", nil)

	//w.Write([]byte("Main page exec"))
}

func (app *application) registerUserForm(w http.ResponseWriter, r *http.Request) {
	app.render(w, http.StatusAccepted, "register.tmpl.html", nil)
}

func (app *application) loginUserForm(w http.ResponseWriter, r *http.Request) {
	app.render(w, http.StatusAccepted, "login.tmpl.html", nil)
}

func (app *application) registerUser(w http.ResponseWriter, r *http.Request) {
	var data UserData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		app.serverError(w, err)
	}

	data.CheckField(validator.NotBlank(data.Password), "Password", "This field can't be blank")
	data.CheckField(validator.NotBlank(data.Username), "Username", "This field can't be blank")
	data.CheckField(validator.CheckPass(data.Password), "Password", "Wrong password schema")
	data.CheckField(validator.CheckUsername(data.Username), "Username", "Wrong username schema")
	check, err := app.users.Exist(data.Username)
	if err != nil {
		app.errorLog.Println(err)
	}
	data.CheckField(!check, "Username", "Already exists")

	if !data.Empty() {
		err := sendJson(w, data.FieldErrors, http.StatusBadRequest)
		if err != nil {
			app.serverError(w, err)
		}
	} else {
		data.AddFieldError("status", "succed")
		err := sendJson(w, data.FieldErrors, http.StatusAccepted)
		if err != nil {
			app.serverError(w, err)
			return
		}
		_, err = app.users.Insert(data.Username, genHash(data.Password))
		if err != nil {
			app.serverError(w, err)
		}
	}
}

func (app *application) loginUser(w http.ResponseWriter, r *http.Request) {
	var data UserData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		app.serverError(w, err)
	}

	ok, err := app.users.Auth(data.Username, data.Password)
	if err != nil {
		app.serverError(w, err)
	}
	if ok == -1 {
		data.AddFieldError("Total", "Wrong Username or Password")
		err := sendJson(w, data.FieldErrors, http.StatusBadRequest)
		if err != nil {
			app.serverError(w, err)
		}
		return
	}
	data.AddFieldError("Total", "Succed login")

	token, err := genToken(data.Username)
	if err != nil {
		app.serverError(w, err)
	}
	cookie := &http.Cookie{
		Name:   "jwtToken",
		Value:  token,
		Path:   "/",
		MaxAge: 3600,
	}
	http.SetCookie(w, cookie)
	err = sendJson(w, data.FieldErrors, http.StatusAccepted)
	if err != nil {
		app.serverError(w, err)
	}
}

func (app *application) tinylinksForm(w http.ResponseWriter, r *http.Request) {
	isLogin, username, err := parseCookie(r)
	if err != nil {
		app.serverError(w, err)
		return
	}
	if !isLogin {
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		return
	}

	userLinks, err := app.links.SelectAllFromUser(username)
	if err != nil {
		app.serverError(w, err)
		return
	}
	app.render(w, http.StatusAccepted, "tinylinks.tmpl.html", &templateData{
		Links: userLinks,
	})
}

func (app *application) tinylinks(w http.ResponseWriter, r *http.Request) {
	isLogin, username, err := parseCookie(r)
	if err != nil {
		app.serverError(w, err)
		return
	}
	var data LinksData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		app.serverError(w, err)
		return
	}
	if !isLogin {
		data.AddFieldError("status", "Unauthorized")
		err := sendJson(w, data.FieldErrors, http.StatusUnauthorized)
		if err != nil {
			app.serverError(w, err)
			return
		}
	}
	data.CheckField(validator.NotBlank(data.Tolink), "Password", "This field can't be blank")
	data.CheckField(validator.NotBlank(data.Userlink), "Username", "This field can't be blank")
	check, err := app.links.Exist(data.Tolink)
	if err != nil {
		app.serverError(w, nil)
	}
	data.CheckField(!check, "Username", "Already exists")
	if !data.Empty() {
		err := sendJson(w, data.FieldErrors, http.StatusBadRequest)
		if err != nil {
			app.serverError(w, err)
		}
	} else {
		_, err := app.links.Insert(data.Userlink, data.Tolink, username)
		if err != nil {
			app.serverError(w, nil)
		}
		data.AddFieldError("status", "succed")
		err = sendJson(w, data.FieldErrors, http.StatusAccepted)
		if err != nil {
			app.serverError(w, err)
			return
		}

	}
}

func (app *application) transfer(w http.ResponseWriter, r *http.Request) {
	tolink := r.PathValue("link")
	check, err := app.links.Exist(tolink)
	if err != nil {
		app.serverError(w, err)
		return
	}
	if !check {
		app.render(w, http.StatusAccepted, "empty.tmpl.html", &templateData{})
		return
	}
	data, err := app.links.SelectToTransfer(tolink)
	if err != nil {
		app.serverError(w, err)
	}
	_, err = app.links.Update(tolink)
	if err != nil {
		app.serverError(w, err)
	}
	http.Redirect(w, r, data.Userlink, http.StatusSeeOther)
}

func (app *application) deleteTinyLink(w http.ResponseWriter, r *http.Request) {

	isLogin, username, err := parseCookie(r)
	if err != nil {
		app.serverError(w, err)
		return
	}
	if !isLogin {
		err := sendJson(w, map[string]string{"status": "Unauthorized"}, http.StatusUnauthorized)
		if err != nil {
			app.serverError(w, err)
		}
		return
	}
	tolink := r.PathValue("link")
	check, err := app.links.Exist(tolink)
	app.infoLog.Println(tolink, " ", check)
	if err != nil {
		app.serverError(w, err)
		return
	}
	if !check {
		err := sendJson(w, map[string]string{"status": "Bad request"}, http.StatusBadRequest)
		if err != nil {
			app.serverError(w, err)
		}
		return
	}
	data, err := app.links.SelectToTransfer(tolink)
	if err != nil {
		app.serverError(w, err)
		return
	}
	if data.Owner != username {
		err := sendJson(w, map[string]string{"status": "Bad request"}, http.StatusBadRequest)
		if err != nil {
			app.serverError(w, err)
		}
		return
	}
	err = sendJson(w, map[string]string{"status": "Accepted"}, http.StatusAccepted)
	if err != nil {
		app.serverError(w, err)
		return
	}
	err = app.links.Delete(tolink)
	if err != nil {
		app.serverError(w, err)
	}

}

func (app *application) logout(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:   "jwtToken",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
