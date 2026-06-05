package logging

import (
	"context"
	"maps"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var resourceTags = map[Tag]bool{
	TagApp: true, TagConnector: true, TagConnPool: true, TagIDP: true,
	TagCert: true, TagAppService: true, TagAgent: true, TagDirectory: true,
	TagAppBundle: true, TagCipher: true, TagPopTraffic: true,
}

// mergeFields classifies tags into structured log fields (source, operation, resource)
// and merges any extra key-value maps. Each tag list should contain at most one source tag,
// one operation tag, and one resource tag; if duplicates exist, the last one wins.
func mergeFields(tags []Tag, extra ...map[string]any) map[string]any {
	// +3 reserves space for "source", "operation", and "resource" keys set by tag classification below
	fields := make(map[string]any, len(extra)+3)
	for _, m := range extra {
		maps.Copy(fields, m)
	}
	for _, t := range tags {
		switch t {
		case TagAPI, TagProvider, TagConfig:
			fields["source"] = string(t)
		case TagCreate, TagRead, TagUpdate, TagDelete,
			TagValidate, TagAssign, TagDeploy, TagList, TagMarshal, TagAuth:
			fields["operation"] = string(t)
		default:
			// Tags not in source or operation categories default to resource; flag unknown ones for detection.
			fields["resource"] = string(t)
			if !resourceTags[t] {
				fields["unknown_tag"] = string(t)
			}
		}
	}
	return fields
}

func formatLogMessage(msg string, tags []Tag) string {
	prefix := FormatTags(tags)
	if prefix == "" {
		return msg
	}
	return prefix + " " + msg
}

// Info logs at INFO level via tflog. Tags are formatted as a bracket-delimited prefix
// and also injected as structured fields. Extra maps are merged into the structured fields.
func Info(ctx context.Context, msg string, tags []Tag, extra ...map[string]any) {
	tflog.Info(ctx, formatLogMessage(msg, tags), mergeFields(tags, extra...))
}

// Debug logs at DEBUG level via tflog.
func Debug(ctx context.Context, msg string, tags []Tag, extra ...map[string]any) {
	tflog.Debug(ctx, formatLogMessage(msg, tags), mergeFields(tags, extra...))
}

// Trace logs at TRACE level via tflog.
func Trace(ctx context.Context, msg string, tags []Tag, extra ...map[string]any) {
	tflog.Trace(ctx, formatLogMessage(msg, tags), mergeFields(tags, extra...))
}

// Warn logs at WARN level via tflog.
func Warn(ctx context.Context, msg string, tags []Tag, extra ...map[string]any) {
	tflog.Warn(ctx, formatLogMessage(msg, tags), mergeFields(tags, extra...))
}

// Error logs at ERROR level via tflog.
func Error(ctx context.Context, msg string, tags []Tag, extra ...map[string]any) {
	tflog.Error(ctx, formatLogMessage(msg, tags), mergeFields(tags, extra...))
}
