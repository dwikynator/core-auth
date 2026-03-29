package errors

import (
	"fmt"

	"github.com/dwikynator/minato/merr"
)

// WithMessage clones a merr.Error and applies a custom message.
func WithMessage(err error, customMsg string) error {
	if customMsg == "" {
		return err
	}

	// If it's a merr.Error, clone it and replace the message
	if e, ok := err.(*merr.Error); ok {
		return &merr.Error{
			Code:     e.Code,
			Reason:   e.Reason,
			Domain:   e.Domain,
			Metadata: e.Metadata,
			Message:  customMsg, // Overwrite just the message!
		}
	}
	// Fallback for non-merr errors
	return fmt.Errorf("%s: %w", customMsg, err)
}
