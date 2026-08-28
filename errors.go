package p3pserver

import (
	"encoding/json"
	"fmt"
)

type Error struct {
	Code       string
	Message    string
	HTTPStatus int
	Details    map[string]interface{}
}

func (e *Error) Error() string { return e.Message }

type CaptureError struct {
	Message string
	Cause   *Error
}

func (e *CaptureError) Error() string { return e.Message }
func (e *CaptureError) Unwrap() error {
	if e.Cause == nil {
		return nil
	}
	return e.Cause
}
func errorFromResponse(status int, raw []byte) *Error {
	var body map[string]interface{}
	_ = json.Unmarshal(raw, &body)
	code, message := "MPP_INTERNAL_ERROR", fmt.Sprintf("HTTP %d", status)
	var details map[string]interface{}
	if nested, ok := body["error"].(map[string]interface{}); ok {
		if v, ok := nested["code"].(string); ok {
			code = v
		}
		if v, ok := nested["message"].(string); ok {
			message = v
		}
		if v, ok := nested["additional_error_details"].(map[string]interface{}); ok {
			details = v
		}
	} else if value, ok := body["error"].(string); ok {
		message = value
		if v, ok := body["code"].(string); ok && v != "" {
			code = v
		}
		if v, ok := body["additional_error_details"].(map[string]interface{}); ok {
			details = v
		}
	} else {
		if v, ok := body["code"].(string); ok && v != "" {
			code = v
		}
		if v, ok := body["message"].(string); ok && v != "" {
			message = v
		}
		if v, ok := body["additional_error_details"].(map[string]interface{}); ok {
			details = v
		}
	}
	return &Error{Code: code, Message: message, HTTPStatus: status, Details: details}
}
