package main

import (
	"github.com/gorilla/mux"
	"net/http"
	"fmt"
	"golang-jwt-api/models"
	"golang-jwt-api/controllers"
	"golang-jwt-api/middleware"
	"golang-jwt-api/config"
)

func main() {
	cfg := config.LoadConfig()

	dbCfg := cfg.Database
	services, err := models.NewServices(
		models.WithGorm(dbCfg.Dialect(), dbCfg.ConnectionInfo()),
		models.WithLogMode(!cfg.IsProd()),
		models.WithUser(cfg.Pepper, cfg.HMACKey, cfg.GetPublicKey(), cfg.GetPrivateKey()),
	)
	must(err)
	defer services.Close()
	services.AutoMigrate()

	r := mux.NewRouter()
	usersC := controllers.NewUsers(services.User)


	userMw := middleware.User{
		UserService: services.User,
	}
	requireUserMw := middleware.RequireUser{
		User: userMw,
	}

	r.HandleFunc("/login", usersC.Login).Methods("POST")
	r.HandleFunc("/create", usersC.Create).Methods("POST")
	r.Handle("/change-password", requireUserMw.ApplyFn(usersC.ChangePassword)).Methods("POST")
	r.Handle("/user", requireUserMw.ApplyFn(usersC.GetUser)).Methods("GET")


	fmt.Printf("Starting the server on :%d...\n", cfg.Port)
	http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), userMw.Apply(r))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
