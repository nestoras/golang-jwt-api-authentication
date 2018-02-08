package models

import (
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
	"golang-jwt-api/hash"
	"regexp"
	"strings"
	"github.com/dgrijalva/jwt-go"
	"crypto/rsa"
	"time"
	"database/sql/driver"
)

type StatusType string

const (
	Active StatusType = "active"
	Inactive StatusType = "inactive"
	Pending StatusType = "pending"
)

func (u *StatusType) Scan(value interface{}) error { *u = StatusType(value.([]byte)); return nil }
func (u StatusType) Value() (driver.Value, error)  { return string(u), nil }

// User represents the user model stored in our database
// This is used for user accounts, storing both an email
// address and a password so users can log in and gain
// access to their content.
type User struct {
	gorm.Model
	Username 	    	 string 		`gorm:"not null;type:varchar(100);unique_index"`
	Email        		 string 		`gorm:"unique_index;type:varchar(100)"`
	Password     		 string 		`gorm:"-" json:"-,omitempty"`
	PasswordHash 		 string 		`gorm:"not null" json:"-"`
	Token	     		 string 		`gorm:"-" json:"Token,omitempty"`
	ChangedPassword  	 time.Time 		`gorm:"type:datetime" json:"-"`
	Status	     		 StatusType		`gorm:"not null;type:ENUM('active', 'inactive', 'pending')" json:"-"`
}

const (
	tokenDuration = 72
	issuer = "famistar"
)

type JWTUser struct {
	ID 		 	 uint	`json:"id"`
	jwt.StandardClaims
}

type Authentication struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}


// UserDB is used to interact with the users database.
type UserDB interface {
	// Methods for querying for single users
	ByID(id uint) (*User, error)
	ByEmail(email string) (*User, error)
	ByUsername(username string) (*User, error)

	// Methods for altering users
	Create(user *User) error
	Update(user *User) error
	Delete(id uint) error
}

// UserService is a set of methods used to manipulate and
// work with the user model
type UserService interface {
	Authenticate(email, password string) (*User, error)
	ByToken(token string) (*User, error)
	ChangePassword(user *User, currentPassword, newPassword, validatePassword string) (*User, error)
	GenerateToken(user *User) (error)
	CreateUserWithToken(user *User) (error)
	UserDB
}


func NewUserService(db *gorm.DB, pepper string, hmacKey string, private *rsa.PrivateKey, public *rsa.PublicKey) UserService {
	ug := &userGorm{db}
	hmac := hash.NewHMAC(hmacKey)
	uv := newUserValidator(ug, hmac, pepper)
	return &userService{
		UserDB: uv,
		pepper: pepper,
		authentication: Authentication{
			privateKey: private,
			publicKey: public,
		},
	}
}

var _ UserService = &userService{}

type userService struct {
	UserDB
	pepper  string
	authentication Authentication
}

// Authenticate can be used to authenticate a user with the
// provided email address and password.
func (us *userService) Authenticate(email, password string) (*User, error) {
	foundUser, err := us.ByEmail(email)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(password+us.pepper))
	if err != nil {
		switch err {
		case bcrypt.ErrMismatchedHashAndPassword:
			return nil, ErrPasswordIncorrect
		default:
			return nil, err
		}
	}

	err = us.GenerateToken(foundUser);
	if err != nil {
		return nil, err
	}

	return foundUser, nil
}

func (us *userService) ChangePassword(user *User, currentPassword, newPassword string, validatePassword string) (*User, error) {
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword+us.pepper))
	if err != nil {
		switch err {
		case bcrypt.ErrMismatchedHashAndPassword:
			return nil, ErrPasswordIncorrect
		default:
			return nil, err
		}
	}

	if currentPassword == newPassword{
		return nil, ErrCannotBeTheSameWithOldPassword
	}

	if validatePassword != newPassword || newPassword == ""{
		return nil, ErrValidatePasswordWrong
	}

	user.Password = newPassword
	user.ChangedPassword = time.Now();
	err = us.Update(user)
	if err != nil {
		return nil, err
	}

	err = us.GenerateToken(user)

	if err != nil {
		return nil, err
	}

	return user, nil
}

type userValFunc func(*User) error

func runUserValFuncs(user *User, fns ...userValFunc) error {
	for _, fn := range fns {
		if err := fn(user); err != nil {
			return err
		}
	}
	return nil
}

var _ UserDB = &userValidator{}

func newUserValidator(udb UserDB, hmac hash.HMAC, pepper string) *userValidator {
	return &userValidator{
		UserDB:     udb,
		hmac:       hmac,
		emailRegex: regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,16}$`),
		pepper:     pepper,
	}
}

type userValidator struct {
	UserDB
	hmac       hash.HMAC
	emailRegex *regexp.Regexp
	pepper     string
}

// ByEmail will normalize the email address before calling
// ByEmail on the UserDB field.
func (uv *userValidator) ByEmail(email string) (*User, error) {
	user := User{
		Email: email,
	}
	if err := runUserValFuncs(&user, uv.normalizeEmail); err != nil {
		return nil, err
	}
	return uv.UserDB.ByEmail(user.Email)
}


// Create will create the provided user and backfill data
// like the ID, CreatedAt, and UpdatedAt fields.
func (uv *userValidator) Create(user *User) error {
	err := runUserValFuncs(user,
		uv.passwordRequired,
		uv.passwordMinLength,
		uv.bcryptPassword,
		uv.passwordHashRequired,
		uv.normalizeEmail,
		uv.requireEmail,
		uv.emailFormat,
		uv.emailIsAvail,
		uv.usernameIsAvail,
		uv.requireUsername)
	if err != nil {
		return err
	}
	return uv.UserDB.Create(user)
}

// Update will hash a remember token if it is provided.
func (uv *userValidator) Update(user *User) error {
	err := runUserValFuncs(user,
		uv.passwordMinLength,
		uv.bcryptPassword,
		uv.passwordHashRequired,
		uv.normalizeEmail,
		uv.requireEmail,
		uv.emailFormat,
		uv.emailIsAvail,
		uv.usernameIsAvail,
		uv.requireUsername)
	if err != nil {
		return err
	}
	return uv.UserDB.Update(user)
}

// Delete will delete the user with the provided ID
func (uv *userValidator) Delete(id uint) error {
	var user User
	user.ID = id
	err := runUserValFuncs(&user, uv.idGreaterThan(0))
	if err != nil {
		return err
	}
	return uv.UserDB.Delete(id)
}

// bcryptPassword will hash a user's password with a
// predefined pepper (userPwPepper) and bcrypt if the
// Password field is not the empty string
func (uv *userValidator) bcryptPassword(user *User) error {
	if user.Password == "" {
		return nil
	}
	pwBytes := []byte(user.Password + uv.pepper)
	hashedBytes, err := bcrypt.GenerateFromPassword(pwBytes, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.PasswordHash = string(hashedBytes)
	user.Password = ""
	return nil
}


func (uv *userValidator) idGreaterThan(n uint) userValFunc {
	return userValFunc(func(user *User) error {
		if user.ID <= n {
			return ErrIDInvalid
		}
		return nil
	})
}

func (uv *userValidator) normalizeEmail(user *User) error {
	user.Email = strings.ToLower(user.Email)
	user.Email = strings.TrimSpace(user.Email)
	return nil
}

func (uv *userValidator) requireEmail(user *User) error {
	if user.Email == "" {
		return ErrEmailRequired
	}
	return nil
}

func (uv *userValidator) requireUsername(user *User) error {
	if user.Username == "" {
		return ErrUsernameRequired
	}
	return nil
}

func (uv *userValidator) emailFormat(user *User) error {
	if user.Email == "" {
		return nil
	}
	if !uv.emailRegex.MatchString(user.Email) {
		return ErrEmailInvalid
	}
	return nil
}

func (uv *userValidator) usernameIsAvail(user *User) error {
	existing, err := uv.ByUsername(user.Username)
	if err == ErrNotFound {
		// Username is not taken
		return nil
	}
	if err != nil {
		return err
	}

	// We found a user w/ this email address...
	// If the found user has the same ID as this user, it is
	// an update and this is the same user.
	if user.ID != existing.ID {
		return ErrUsernameTaken
	}
	return nil
}

func (uv *userValidator) emailIsAvail(user *User) error {
	existing, err := uv.ByEmail(user.Email)
	if err == ErrNotFound {
		// Email address is not taken
		return nil
	}
	if err != nil {
		return err
	}

	// We found a user w/ this email address...
	// If the found user has the same ID as this user, it is
	// an update and this is the same user.
	if user.ID != existing.ID {
		return ErrEmailTaken
	}
	return nil
}

func (uv *userValidator) passwordMinLength(user *User) error {
	if user.Password == "" {
		return nil
	}
	if len(user.Password) < 8 {
		return ErrPasswordTooShort
	}
	return nil
}

func (uv *userValidator) passwordRequired(user *User) error {
	if user.Password == "" {
		return ErrPasswordRequired
	}
	return nil
}

func (uv *userValidator) passwordHashRequired(user *User) error {
	if user.PasswordHash == "" {
		return ErrPasswordRequired
	}
	return nil
}

var _ UserDB = &userGorm{}

type userGorm struct {
	db *gorm.DB
}

// ByID will look up a user with the provided ID.
// If the user is found, we will return a nil error
// If the user is not found, we will return ErrNotFound
// If there is another error, we will return an error with
// more information about what went wrong. This may not be
// an error generated by the models package.
//
// As a general rule, any error but ErrNotFound should
// probably result in a 500 error.
func (ug *userGorm) ByID(id uint) (*User, error) {
	var user User
	db := ug.db.Where("id = ?", id)
	err := first(db, &user)
	return &user, err
}

// ByEmail looks up a user with the given email address and
// returns that user.
func (ug *userGorm) ByEmail(email string) (*User, error) {
	var user User
	db := ug.db.Where("email = ?", email)
	err := first(db, &user)
	return &user, err
}

// ByUsername looks up a user with the given username and
// returns that user.
func (ug *userGorm) ByUsername(username string) (*User, error) {
	var user User
	db := ug.db.Where("username = ?", username)
	err := first(db, &user)
	return &user, err
}


func (us *userService) ByToken(tokenString string) (*User, error) {
	jwtUser := JWTUser{}
	token, err := jwt.ParseWithClaims(tokenString, &jwtUser, func(token *jwt.Token) (interface{}, error) {
		return us.authentication.publicKey, nil
	})

	if err != nil {
		return nil, ErrWrongToken
	}

	if jwtUser.ID < 1 && !token.Valid {
		return nil, ErrPasswordRequired
	}


	if jwtUser.StandardClaims.ExpiresAt > time.Now().UnixNano() {
		return nil, ErrTokenExpired
	}

	if jwtUser.StandardClaims.Issuer != issuer {
		return nil, ErrWrongToken
	}

	foundUser, err := us.ByID(jwtUser.ID)
	if jwtUser.StandardClaims.IssuedAt <= foundUser.ChangedPassword.Unix() {
		return nil, ErrTokenExpired
	}

	if err != nil {
		return nil, err
	}

	return foundUser, nil
}

// Create will create the provided user and backfill data
// like the ID, CreatedAt, and UpdatedAt fields.
func (ug *userGorm) Create(user *User) error {
	err :=  ug.db.Create(user).Error
	if err != nil{
		return err
	}
	return nil
}

// Update will update the provided user with all of the data
// in the provided user object.
func (ug *userGorm) Update(user *User) error {
	return ug.db.Save(user).Error
}

// Delete will delete the user with the provided ID
func (ug *userGorm) Delete(id uint) error {
	user := User{Model: gorm.Model{ID: id}}
	return ug.db.Delete(&user).Error
}

// first will query using the provided gorm.DB and it will
// get the first item returned and place it into dst. If
// nothing is found in the query, it will return ErrNotFound
func first(db *gorm.DB, dst interface{}) error {
	err := db.First(dst).Error
	if err == gorm.ErrRecordNotFound {
		return ErrNotFound
	}
	return err
}

// Generate Token can be used to create a valid token for a user
func (us *userService) GenerateToken(user *User) error{
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, &JWTUser{
		ID: user.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(tokenDuration)).Unix(),
			IssuedAt: time.Now().Unix(),
			Issuer: issuer,
		},
	})

	tokenString, err := token.SignedString(us.authentication.privateKey)
	if err != nil {
		return ErrSignedStringToken
	}
	user.Token = tokenString
	return nil
}


func (us *userService) CreateUserWithToken(user *User) error{
	if err := us.Create(user); err != nil {
		return err
	}

	if err := us.GenerateToken(user); err != nil {
		return err
	}
	return nil
}
