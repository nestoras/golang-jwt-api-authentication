package models

import (
	"strings"
)

var (
	// ErrNotFound is returned when a resource cannot be found
	// in the database.
	ErrNotFound modelError = "models: resource not found"
	// ErrPasswordIncorrect is returned when an invalid password
	// is used when attempting to authenticate a user.
	ErrPasswordIncorrect modelError = "models: incorrect password provided"
	// ErrEmailRequired is returned when an email address is
	// not provided when creating a user
	ErrEmailRequired modelError = "models: email address is required"
	// ErrEmailRequired is returned when an email address is
	// not provided when creating a user
	ErrUsernameRequired modelError = "models: username is required"
	// ErrEmailInvalid is returned when an email address provided
	// does not match any of our requirements
	ErrEmailInvalid modelError = "models: email address is not valid"
	// ErrEmailTaken is returned when an update or create is attempted
	// with an email address that is already in use.
	ErrEmailTaken modelError = "models: email address is already taken"
	ErrUsernameTaken modelError = "models: username is already taken"
	// ErrPasswordRequired is returned when a create is attempted
	// without a user password provided.
	ErrPasswordRequired modelError = "models: password is required"
	// ErrPasswordTooShort is returned when an update or create is
	// attempted with a user password that is less than 8 characters.
	ErrPasswordTooShort modelError = "models: password must be at least 8 characters long"
	ErrTitleRequired    modelError = "models: title is required"
	ErrValidatePasswordWrong modelError = "models: New password and validate password must be the same or not provided"
	ErrCannotBeTheSameWithOldPassword modelError = "models: New password cannot be the same with the old password"
	ErrWrongToken modelError = "models: The access token provided is invalid."
	ErrTokenExpired modelError = "models: The access token provided is expired."
	// ErrIDInvalid is returned when an invalid ID is provided
	// to a method like Delete.
	ErrIDInvalid privateError = "models: ID provided was invalid"
	// ErrRememberRequired is returned when a create or update
	// is attempted without a user remember token hash
	ErrRememberRequired privateError = "models: remember token is required"
	// ErrRememberTooShort is returned when a remember token is
	// not at least 32 bytes
	ErrRememberTooShort privateError = "models: remember token must be at least 32 bytes"
	ErrUserIDRequired   privateError = "models: user ID is required"
	ErrSignedStringToken privateError = "models: Cannot create token"
)

type modelError string

func (e modelError) Error() string {
	return string(e)
}

func (e modelError) Public() string {
	s := strings.Replace(string(e), "models: ", "", 1)
	split := strings.Split(s, " ")
	split[0] = strings.Title(split[0])
	return strings.Join(split, " ")
}

type privateError string

func (e privateError) Error() string {
	return string(e)
}