package views

import (
	"net/http"
	"encoding/json"
)

// Render is used to render the view with the predefined layout.
func Render(w http.ResponseWriter, r *http.Request, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	var vd Data
	switch d := data.(type) {
	case Data:
		vd = d
	default:
		vd = Data{
			Result: data,
		}
	}

	response, err := json.Marshal(vd)
	if err != nil {

	}
	w.Write(response)
}
