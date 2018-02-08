package controllers

import (
	"net/http"
	"golang-jwt-api/models"
	"golang-jwt-api/views"
	"golang-jwt-api/context"
)

type Users struct {
	us        models.UserService
}

func NewUsers(us models.UserService) *Users {
	return &Users{
		us:        us,
	}
}

type LoginForm struct {
	Email    string `schema:"email"`
	Password string `schema:"password"`
}

// Login is used to verify the provided email address and
// password and then log the user in if they are correct.
//
// POST /login
func (u *Users) Login(w http.ResponseWriter, r *http.Request) {
	form := LoginForm{}
	var vd views.Data

	if err := parseForm(r, &form); err != nil {
		vd.SetError(err)
		views.Render(w,r,err)
		return
	}

	user, err := u.us.Authenticate(form.Email, form.Password)
	if err != nil {
		vd.SetError(err)
		views.Render(w,r,vd)
		return
	}

	views.Render(w,r,user)
}

type SignupForm struct {
	Username string `schema:"username"`
	Email    string `schema:"email"`
	Password string `schema:"password"`
}


// Login is used to verify the provided email address and
// password and then log the user in if they are correct.
//
// POST /create
func (u *Users) Create(w http.ResponseWriter, r *http.Request) {
	var form SignupForm
	var vd views.Data
	parseURLParams(r, &form)
	if err := parseForm(r, &form); err != nil {
		vd.SetError(err)
		views.Render(w,r,vd)
		return
	}

	user := models.User{
		Username: form.Username,
		Email:    form.Email,
		Password: form.Password,
	}

	if err := u.us.CreateUserWithToken(&user); err != nil {
		vd.SetError(err)
		views.Render(w,r,vd)
		return
	}
	views.Render(w,r,user)
}

type ChangePasswordForm struct {
	CurrentPassword	 	string `schema:"current_password"`
	NewPassword	  		string `schema:"new_password"`
	RepeatedPassword	string `schema:"repeated_password"`
}

// Change password for the current user
//
// GET /user
func (u *Users) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var form ChangePasswordForm
	var vd views.Data
	parseURLParams(r, &form)
	user := context.User(r.Context())

	if err := parseForm(r, &form); err != nil {
		vd.SetError(err)
		views.Render(w,r,vd)
		return
	}

	foundUser, err := u.us.ChangePassword(user, form.CurrentPassword, form.NewPassword, form.RepeatedPassword);
	if  err != nil {
		vd.SetError(err)
		views.Render(w,r,vd)
		return
	}
	views.Render(w,r,foundUser)
}

// Get the current user
//
// GET /user
func (u *Users) GetUser(w http.ResponseWriter, r *http.Request) {
	user := context.User(r.Context())
	views.Render(w,r,user)
}

