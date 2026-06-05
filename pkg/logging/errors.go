package logging

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Tag classifies a log or error entry by source, operation, or resource.
type Tag string

const (
	// TagAPI indicates the operation involves an API call.
	TagAPI Tag = "API"
	// TagProvider indicates the operation involves the Terraform provider.
	TagProvider Tag = "PROVIDER"
	// TagConfig indicates a configuration-related operation.
	TagConfig Tag = "CONFIG"

	// TagApp identifies the application resource.
	TagApp Tag = "APP"
	// TagConnector identifies the connector resource.
	TagConnector Tag = "CONNECTOR"
	// TagConnPool identifies the connector pool resource.
	TagConnPool Tag = "CONN_POOL"
	// TagIDP identifies the identity provider resource.
	TagIDP Tag = "IDP"
	// TagCert identifies the certificate resource.
	TagCert Tag = "CERT"
	// TagAppService identifies the application service resource.
	TagAppService Tag = "APP_SVC"
	// TagAgent identifies the agent resource.
	TagAgent Tag = "AGENT"
	// TagDirectory identifies the directory resource.
	TagDirectory Tag = "DIRECTORY"
	// TagAppBundle identifies the app bundle resource.
	TagAppBundle Tag = "APP_BUNDLE"
	// TagCipher identifies the cipher suite resource.
	TagCipher Tag = "CIPHER"
	// TagPopTraffic identifies the POP traffic resource.
	TagPopTraffic Tag = "POP_TRAFFIC"

	// TagCreate identifies a create operation.
	TagCreate Tag = "CREATE"
	// TagRead identifies a read operation.
	TagRead Tag = "READ"
	// TagUpdate identifies an update operation.
	TagUpdate Tag = "UPDATE"
	// TagDelete identifies a delete operation.
	TagDelete Tag = "DELETE"
	// TagValidate identifies a validation operation.
	TagValidate Tag = "VALIDATE"
	// TagAssign identifies an assign operation.
	TagAssign Tag = "ASSIGN"
	// TagDeploy identifies a deploy operation.
	TagDeploy Tag = "DEPLOY"
	// TagList identifies a list operation.
	TagList Tag = "LIST"
	// TagMarshal identifies a marshaling operation.
	TagMarshal Tag = "MARSHAL"
	// TagAuth identifies an authentication-related operation.
	TagAuth Tag = "AUTH"
)

// EAAError is a tagged error that carries structured context for logging and diagnostic classification.
type EAAError struct {
	wrapped error
	message string
	tags    []Tag
}

func (e *EAAError) Error() string {
	prefix := FormatTags(e.tags)
	msg := e.message
	if prefix != "" {
		msg = prefix + " " + msg
	}
	if e.wrapped != nil {
		msg += ": " + e.wrapped.Error()
	}
	return msg
}

// Unwrap returns the underlying wrapped error, if any.
func (e *EAAError) Unwrap() error { return e.wrapped }

// Message returns just the outer message without the wrapped error.
func (e *EAAError) Message() string { return e.message }

// HasTag reports whether this error contains the given tag.
func (e *EAAError) HasTag(t Tag) bool {
	return slices.Contains(e.tags, t)
}

// Tags returns the tags associated with this error.
func (e *EAAError) Tags() []Tag {
	return slices.Clone(e.tags)
}

// FormatTags formats a slice of tags as bracket-delimited prefixes, e.g. "[API][APP]".
func FormatTags(tags []Tag) string {
	var b strings.Builder
	for _, t := range tags {
		b.WriteByte('[')
		b.WriteString(string(t))
		b.WriteByte(']')
	}
	return b.String()
}

// Errorf creates a new EAAError with the given tags and formatted message.
func Errorf(tags []Tag, format string, args ...any) *EAAError {
	return &EAAError{
		tags:    slices.Clone(tags),
		message: fmt.Sprintf(format, args...),
	}
}

// Wrapf wraps an existing error in an EAAError, adding tags and a formatted message.
// If err is nil, it delegates to Errorf (no wrapped cause to preserve).
func Wrapf(err error, tags []Tag, format string, args ...any) *EAAError {
	if err == nil {
		return Errorf(tags, format, args...)
	}
	return &EAAError{
		tags:    slices.Clone(tags),
		message: fmt.Sprintf(format, args...),
		wrapped: err,
	}
}

// HasTag reports whether err (or any error in its chain) is an *EAAError containing the given tag.
func HasTag(err error, t Tag) bool {
	if eaaErr, ok := errors.AsType[*EAAError](err); ok {
		return eaaErr.HasTag(t)
	}
	return false
}
