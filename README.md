# Welcome to Golang JWT API with Gorm

Warning this project is under development, use it with caution.

If you want to contribute or help you are welcome!

Golang JWT API is a RESTFUL API Authentication System

### How to use endpoints without authorization:
r.HandleFunc("/login", usersC.Login).Methods("POST")

### How to use endpoint that required authorization:
r.Handle("/user", requireUserMw.ApplyFn(usersC.GetUser)).Methods("GET")

### Start the web server:
    go run main.go

### Run tests
    go test  $(go list ./... | grep -v /vendor/)


Go to http://localhost:3000/ *port is configurable and you must see your own configuration

