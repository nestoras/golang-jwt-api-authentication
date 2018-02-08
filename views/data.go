package views

import (
	"log"
)

const (
	// AlertMsgGeneric is displayed when any random error
	// is encountered by our backend.
	AlertMsgGeneric = "Something went wrong. Please try again, and contact us if the problem persists."
)

// Error is used to render API response
type Error struct {
	Message string	`json:"message"`
}

// Data is the top level structure that views expect data
// to come in.
type Data struct {
	Error *Error		`json:"error,omitempty"`
	Result interface{}	`json:"result,omitempty"`
}

func (d *Data) SetError(err error) {
	if pErr, ok := err.(PublicError); ok {
		d.Error = &Error{
			Message: pErr.Public(),
		}
	} else {
		log.Println(err)
		d.Error = &Error{
			Message: AlertMsgGeneric,
		}
	}
}

func (d *Data) AlertError(msg string) {
	d.Error = &Error{
		Message: msg,
	}
}

type PublicError interface {
	error
	Public() string
}



