package middleware

import (
	"net/http"
	"golang-jwt-api/models"
	"golang-jwt-api/context"
	"golang-jwt-api/views"
	"strings"
)

type User struct {
	models.UserService
}

func (mw *User) Apply(next http.Handler) http.HandlerFunc {
	return mw.ApplyFn(next.ServeHTTP)
}

func (mw *User) ApplyFn(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
			tokenStr := bearer[7:]
			user, err := mw.UserService.ByToken(tokenStr)
			if err != nil {
				next(w, r)
				return
			}
			ctx := r.Context()
			ctx = context.WithUser(ctx, user)
			r = r.WithContext(ctx)
			next(w, r)
		}else{
			next(w, r)
			return
		}
	})
}

// RequireUser assumes that User middleware has already been run
// otherwise it will no work correctly.
type RequireUser struct {
	User
}

// Apply assumes that User middleware has already been run
// otherwise it will no work correctly.
func (mw *RequireUser) Apply(next http.Handler) http.HandlerFunc {
	return mw.ApplyFn(next.ServeHTTP)
}

// ApplyFn assumes that User middleware has already been run
// otherwise it will no work correctly.
func (mw *RequireUser) ApplyFn(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := context.User(r.Context())
		var vd views.Data
		if user == nil {
			vd.SetError(models.ErrWrongToken)
			views.Render(w,r, vd)
			return
		}
		next(w, r)
	})
}

