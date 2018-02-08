package models

import (
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"testing"
	"golang-jwt-api/config"
	"github.com/jinzhu/gorm"
)

var userServiceTest UserService
var mockDb *gorm.DB
var mockConfig config.Config

func init()  {
	testCfg := config.LoadTestConfig();
	db := config.GetMockDatabase(testCfg.Database)
	us := NewUserService(db, testCfg.Pepper, testCfg.HMACKey, testCfg.GetPrivateKey(), testCfg.GetPublicKey())
	db.LogMode(false)
	// Clear the users table between tests
	err := db.DropTableIfExists(&User{}).Error
	if err != nil {
		panic(err)
	}
	db.AutoMigrate(&User{})
	userServiceTest = us
	mockDb = db
	mockConfig = testCfg
}

func TestCreate(t *testing.T) {
	tests := []struct {
		name    string
		args    User
		want    interface{}
		wantErr bool
	}{
		{"Create a user", User{Username: "test", Email: "test@test.com", Password: "12345678"}, nil, false},
		{"Create a user with the same username", User{Username: "test", Email: "test2@test.com", Password: "12345678"}, ErrUsernameTaken, true},
		{"Create a user with the same email", User{Username: "test2", Email: "test@test.com", Password: "12345678"}, ErrEmailTaken, true},
		{"Create a user with five digit password", User{Username: "test2", Email: "test@test.com", Password: "12345"}, ErrPasswordTooShort, true},
		{"Create a user with empty password", User{Username: "test2", Email: "test@test.com", Password: ""}, ErrPasswordRequired, true},
		{"Create a user with wrong email", User{Username: "test2", Email: "test", Password: "12345678"}, ErrEmailInvalid, true},
		{"Create a user without email", User{Username: "test2", Email: "", Password: "12345678"}, ErrEmailRequired, true},
		{"Create a user without username", User{Username: "", Email: "test22@email.com", Password: "12345678"}, ErrUsernameRequired, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := userServiceTest.Create(&tt.args)
			if (err != nil) != tt.wantErr || err != tt.want {
				t.Errorf("UserTest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}

	return
}


func TestUpdate(t *testing.T) {

	user, err := userServiceTest.ByUsername("test")
	if (err != nil) {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		args    User
		want    interface{}
		wantErr bool
	}{
		{"Update a user", *user, nil, false},
		{"Update a user without email", User{ Username: "test23", Email: "", Password: "12345678"}, ErrEmailRequired, true},
		{"Update a user with the same username", User{Username: "test", Email: "test2@test.com", Password: "12345678"}, ErrUsernameTaken, true},
		//{"Update a user with the same email", User{Username: "test2", Email: "test@test.com", Password: "12345678"}, ErrEmailTaken, true},
		{"Update a user with five digit password", User{Username: "test2", Email: "test@test.com", Password: "12345"}, ErrPasswordTooShort, true},
		{"Update a user with empty password", User{Username: "test2", Email: "test@test.com", Password: ""}, ErrPasswordRequired, true},
		{"Update a user with wrong email", User{Username: "test2", Email: "test", Password: "12345678"}, ErrEmailInvalid, true},
		{"Update a user without email", User{Username: "test2", Email: "", Password: "12345678"}, ErrEmailRequired, true},
		{"Update a user without username", User{Username: "", Email: "test22@email.com", Password: "12345678"}, ErrUsernameRequired, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := userServiceTest.Update(&tt.args)
			if (err != nil) != tt.wantErr || err != tt.want {
				t.Errorf("UserTest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			//if !reflect.DeepEqual(got, tt.want) {
			//	t.Errorf("NewServices() = %v, want %v", got, tt.want)
			//}
		})
	}

	return
}

func TestUserGorm_ByUsername(t *testing.T) {
	var user User
	tests := []struct {
		name    	string
		args	    string
		want    	interface{}
		wantErr 	bool
	}{
		{"Find a user in database by username", "test", nil, false},
		{"Not found a user in database by username", "test_not_exist", ErrNotFound, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := mockDb.Where("username = ?", tt.args)
			err := first(query, &user)
			if (err != nil) != tt.wantErr || err != tt.want {
				t.Errorf("UserTest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
	return
}

func TestUserService_GenerateToken(t *testing.T) {
	user, err := userServiceTest.ByUsername("test")
	if (err != nil) {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		args    *User
		want    interface{}
		wantErr bool
	}{
		{"Generate token for a user", user, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := userServiceTest.GenerateToken(tt.args)
			if (err != nil) != tt.wantErr || err != tt.want {
				t.Errorf("UserTest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}


func TestUserService_Authenticate(t *testing.T) {
	type LoginFormTest struct {
		email string
		password string
	}

	tests := []struct {
		name    string
		args    LoginFormTest
		want    interface{}
		wantErr bool
	}{
		{"Authenticate a user", LoginFormTest{email:"test@email.com" , password: "12345678"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := userServiceTest.Authenticate(tt.args.email,tt.args.password)
			if (err != nil) != tt.wantErr || err != tt.want {
				t.Errorf("UserTest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}