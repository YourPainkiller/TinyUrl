package validator

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

type Validator struct {
	FieldErrors map[string]string
}

func (v *Validator) Empty() bool {
	return len(v.FieldErrors) == 0
}

func (v *Validator) Matches(value string, rx *regexp.Regexp) bool {
	return rx.MatchString(value)
}

func (v *Validator) AddFieldError(key, message string) {
	if v.FieldErrors == nil {
		v.FieldErrors = make(map[string]string)
	}

	if _, exists := v.FieldErrors[key]; !exists {
		v.FieldErrors[key] = message
	}
}

func (v *Validator) CheckField(ok bool, key, message string) {
	if !ok {
		v.AddFieldError(key, message)
	}
}

func NotBlank(value string) bool {
	return strings.TrimSpace(value) != ""
}

func MaxChar(value string, n int) bool {
	return utf8.RuneCountInString(value) <= n
}

func CheckPass(value string) bool {
	whitelist := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+={[}]|\\:;\"'<,>.?/"
	if len(value) < 1 && len(value) > 99 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune(whitelist, char) {
			return false
		}
	}
	return true
}

func CheckUsername(value string) bool {
	whitelist := "abcdefghijklmnopqrstuvwxyz1234567890_"
	if len(value) < 1 && len(value) > 99 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune(whitelist, char) {
			return false
		}
	}
	return true
}
