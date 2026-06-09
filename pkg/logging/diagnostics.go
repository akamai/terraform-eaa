package logging

import (
	"errors"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
)

// DiagError converts an error into a single error-severity Terraform diagnostic.
// For EAAError, Summary contains only the outer message (with tags) and Detail contains the wrapped cause.
// For other errors, Summary is the full error string.
func DiagError(err error) diag.Diagnostics {
	if err == nil {
		return nil
	}
	d := diag.Diagnostic{
		Severity: diag.Error,
	}
	if eaaErr, ok := errors.AsType[*EAAError](err); ok {
		d.Summary = formatLogMessage(eaaErr.Message(), eaaErr.tags)
		if inner := eaaErr.Unwrap(); inner != nil {
			d.Detail = inner.Error()
		}
	} else {
		d.Summary = err.Error()
		if unwrapper, ok := err.(interface{ Unwrap() error }); ok {
			if inner := unwrapper.Unwrap(); inner != nil {
				d.Detail = inner.Error()
			}
		}
	}
	return diag.Diagnostics{d}
}

// DiagWarning converts an error into a single warning-severity Terraform diagnostic.
// For EAAError, Summary contains only the outer message (with tags) and Detail contains the wrapped cause.
// For other errors, Summary is the full error string.
func DiagWarning(err error) diag.Diagnostics {
	if err == nil {
		return nil
	}
	d := diag.Diagnostic{
		Severity: diag.Warning,
	}
	if eaaErr, ok := errors.AsType[*EAAError](err); ok {
		d.Summary = formatLogMessage(eaaErr.Message(), eaaErr.tags)
		if inner := eaaErr.Unwrap(); inner != nil {
			d.Detail = inner.Error()
		}
	} else {
		d.Summary = err.Error()
		if unwrapper, ok := err.(interface{ Unwrap() error }); ok {
			if inner := unwrapper.Unwrap(); inner != nil {
				d.Detail = inner.Error()
			}
		}
	}
	return diag.Diagnostics{d}
}

// DiagErrorf creates a new EAAError from the given tags and format string, and returns it as an error diagnostic.
func DiagErrorf(tags []Tag, format string, args ...any) diag.Diagnostics {
	return DiagError(Errorf(tags, format, args...))
}

// DiagWarningf creates a new EAAError from the given tags and format string, and returns it as a warning diagnostic.
func DiagWarningf(tags []Tag, format string, args ...any) diag.Diagnostics {
	return DiagWarning(Errorf(tags, format, args...))
}

// DiagFromErr wraps an existing error with tags and a message, and returns it as an error diagnostic.
func DiagFromErr(err error, tags []Tag, msg string) diag.Diagnostics {
	return DiagError(Wrapf(err, tags, "%s", msg))
}

// DiagFromErrf wraps an existing error with tags and a formatted message, and returns it as an error diagnostic.
func DiagFromErrf(err error, tags []Tag, format string, args ...any) diag.Diagnostics {
	return DiagError(Wrapf(err, tags, format, args...))
}
