package helpers

import "regexp"

func normalizePhoneNumber(phone string) string {
	re := regexp.MustCompile("\\D")
	return re.ReplaceAllString(phone, "")
}