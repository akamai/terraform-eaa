package logging

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

type Tag string

const (
	// TagAPI indicates the error originated from an API call.
	TagAPI Tag = "API"
	// TagProvider indicates the error originated from the Terraform provider.
	TagProvider Tag = "PROVIDER"
	// TagConfig indicates a configuration error.
	TagConfig Tag = "CONFIG"
	// TagAuth identifies authentication-related operations.
	TagAuth Tag = "AUTH"

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
)

type EAAError struct {
	Wrapped error
	Message string
	Tags    []Tag
}

func (e *EAAError) Error() string {
	prefix := FormatTags(e.Tags)
	msg := e.Message
	if prefix != "" {
		msg = prefix + " " + msg
	}
	if e.Wrapped != nil {
		msg += ": " + e.Wrapped.Error()
	}
	return msg
}

func (e *EAAError) Unwrap() error { return e.Wrapped }

func (e *EAAError) HasTag(t Tag) bool {
	return slices.Contains(e.Tags, t)
}

func FormatTags(tags []Tag) string {
	var b strings.Builder
	for _, t := range tags {
		b.WriteByte('[')
		b.WriteString(string(t))
		b.WriteByte(']')
	}
	return b.String()
}

func Errorf(tags []Tag, format string, args ...any) *EAAError {
	return &EAAError{
		Tags:    tags,
		Message: fmt.Sprintf(format, args...),
	}
}

func Wrapf(err error, tags []Tag, format string, args ...any) *EAAError {
	return &EAAError{
		Tags:    tags,
		Message: fmt.Sprintf(format, args...),
		Wrapped: err,
	}
}

func HasTag(err error, t Tag) bool {
	if eaaErr, ok := errors.AsType[*EAAError](err); ok {
		return eaaErr.HasTag(t)
	}
	return false
}
