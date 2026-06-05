package logging

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatTags(t *testing.T) {
	tests := map[string]struct {
		want string
		tags []Tag
	}{
		"nil tags":      {tags: nil, want: ""},
		"empty tags":    {tags: []Tag{}, want: ""},
		"single tag":    {tags: []Tag{TagAPI}, want: "[API]"},
		"multiple tags": {tags: []Tag{TagAPI, TagApp, TagCreate}, want: "[API][APP][CREATE]"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, FormatTags(tt.tags))
		})
	}
}

func TestEAAError_Error(t *testing.T) {
	tests := map[string]struct {
		err  *EAAError
		want string
	}{
		"no tags no wrap": {
			err:  &EAAError{message: "something failed"},
			want: "something failed",
		},
		"with tags": {
			err:  &EAAError{tags: []Tag{TagAPI, TagApp}, message: "create failed"},
			want: "[API][APP] create failed",
		},
		"with wrapped error": {
			err:  &EAAError{tags: []Tag{TagAPI}, message: "request failed", wrapped: fmt.Errorf("connection refused")},
			want: "[API] request failed: connection refused",
		},
		"empty message with tags": {
			err:  &EAAError{tags: []Tag{TagCreate}, message: ""},
			want: "[CREATE] ",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}

func TestEAAError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("inner error")
	err := Wrapf(inner, []Tag{TagAPI}, "outer")
	require.Equal(t, inner, err.Unwrap())

	errNoWrap := Errorf([]Tag{TagAPI}, "standalone")
	require.Nil(t, errNoWrap.Unwrap())
}

func TestEAAError_ErrorsIs(t *testing.T) {
	sentinel := fmt.Errorf("sentinel")
	wrapped := Wrapf(sentinel, []Tag{TagAPI, TagApp}, "wrapped")

	require.True(t, errors.Is(wrapped, sentinel))
	require.False(t, errors.Is(wrapped, fmt.Errorf("other")))
}

func TestEAAError_ErrorsIsChain(t *testing.T) {
	sentinel := fmt.Errorf("sentinel")
	inner := Wrapf(sentinel, []Tag{TagAPI}, "inner")
	outer := fmt.Errorf("outer: %w", inner)

	require.True(t, errors.Is(outer, sentinel))
}

func TestErrorf(t *testing.T) {
	err := Errorf([]Tag{TagAPI, TagCreate}, "failed to create %s", "app")

	require.Equal(t, "[API][CREATE] failed to create app", err.Error())
	require.Nil(t, err.Unwrap())
	require.True(t, err.HasTag(TagAPI))
	require.True(t, err.HasTag(TagCreate))
	require.False(t, err.HasTag(TagDelete))
}

func TestWrapf(t *testing.T) {
	inner := fmt.Errorf("timeout")
	err := Wrapf(inner, []Tag{TagAPI, TagApp}, "request failed")

	require.Equal(t, "[API][APP] request failed: timeout", err.Error())
	require.Equal(t, inner, err.Unwrap())
	require.True(t, err.HasTag(TagAPI))
}

func TestWrapf_NilError(t *testing.T) {
	err := Wrapf(nil, []Tag{TagAPI}, "no cause")

	require.Equal(t, "[API] no cause", err.Error())
	require.Nil(t, err.Unwrap())
}

func TestErrorf_DefensiveCopy(t *testing.T) {
	tags := []Tag{TagAPI, TagApp}
	err := Errorf(tags, "test")
	tags[0] = TagProvider

	require.True(t, err.HasTag(TagAPI), "mutating original slice should not affect the error")
}

func TestHasTag_PackageLevel(t *testing.T) {
	tests := map[string]struct {
		err  error
		tag  Tag
		want bool
	}{
		"EAAError with tag": {
			err:  Errorf([]Tag{TagAPI, TagCreate}, "test"),
			tag:  TagAPI,
			want: true,
		},
		"EAAError without tag": {
			err:  Errorf([]Tag{TagAPI}, "test"),
			tag:  TagDelete,
			want: false,
		},
		"non-EAAError": {
			err:  fmt.Errorf("plain error"),
			tag:  TagAPI,
			want: false,
		},
		"nil error": {
			err:  nil,
			tag:  TagAPI,
			want: false,
		},
		"wrapped EAAError": {
			err:  fmt.Errorf("outer: %w", Errorf([]Tag{TagApp, TagRead}, "inner")),
			tag:  TagApp,
			want: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, HasTag(tt.err, tt.tag))
		})
	}
}

func TestEAAError_Tags(t *testing.T) {
	err := Errorf([]Tag{TagAPI, TagApp, TagCreate}, "test")
	assert.Equal(t, []Tag{TagAPI, TagApp, TagCreate}, err.Tags())
}

func TestEAAError_Tags_DefensiveCopy(t *testing.T) {
	err := Errorf([]Tag{TagAPI, TagApp}, "test")
	tags := err.Tags()
	tags[0] = TagDelete

	assert.True(t, err.HasTag(TagAPI), "mutating returned slice should not affect the error")
}

func TestWrapf_DefensiveCopy(t *testing.T) {
	inner := fmt.Errorf("inner")
	tags := []Tag{TagAPI, TagApp}
	err := Wrapf(inner, tags, "test")
	tags[0] = TagProvider

	assert.True(t, err.HasTag(TagAPI), "mutating original slice should not affect the error")
}

func TestWrapf_NilDelegatesToErrorf(t *testing.T) {
	err := Wrapf(nil, []Tag{TagAPI}, "no cause: %s", "test")

	assert.Equal(t, "[API] no cause: test", err.Error())
	assert.Nil(t, err.Unwrap())
	assert.True(t, err.HasTag(TagAPI))
}
