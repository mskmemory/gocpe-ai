package service

import (
	"context"
	"errors"
)

type Fault struct {
	Status        int
	Code, Message string
	Details       []ErrorDetail
}

func (e *Fault) Error() string { return e.Code }
func Invalid(pointer, message string) *Fault {
	return &Fault{Status: 422, Code: "INVALID_INPUT", Message: "Request validation failed", Details: []ErrorDetail{{Pointer: pointer, Message: message}}}
}
func Unavailable() *Fault {
	return &Fault{Status: 503, Code: "SERVICE_UNAVAILABLE", Message: "Storage or resolution worker is not available"}
}
func AsFault(err error) *Fault {
	var f *Fault
	if errors.As(err, &f) {
		return f
	}
	switch {
	case errors.Is(err, ErrNotFound):
		return &Fault{Status: 404, Code: "NOT_FOUND", Message: "Resource not found"}
	case errors.Is(err, ErrConflict):
		return &Fault{Status: 409, Code: "IDEMPOTENCY_CONFLICT", Message: "Key was already used for another request"}
	case errors.Is(err, ErrUnavailable), errors.Is(err, context.DeadlineExceeded):
		return Unavailable()
	case errors.Is(err, ErrRateLimited):
		return &Fault{Status: 429, Code: "RATE_LIMITED", Message: "Admission limit reached"}
	default:
		return &Fault{Status: 500, Code: "INTERNAL_ERROR", Message: "Internal server error"}
	}
}
