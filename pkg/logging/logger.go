package logging

import (
	"context"
	"maps"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

func mergeFields(tags []Tag, extra ...map[string]any) map[string]any {
	fields := make(map[string]any, len(extra)+2)
	for _, m := range extra {
		maps.Copy(fields, m)
	}
	for _, t := range tags {
		switch t {
		case TagAPI, TagProvider, TagConfig, TagAuth:
			fields["source"] = string(t)
		case TagCreate, TagRead, TagUpdate, TagDelete,
			TagValidate, TagAssign, TagDeploy, TagList, TagMarshal:
			fields["operation"] = string(t)
		default:
			fields["resource"] = string(t)
		}
	}
	return fields
}

func Info(ctx context.Context, msg string, tags []Tag, extra ...map[string]any) {
	tflog.Info(ctx, FormatTags(tags)+" "+msg, mergeFields(tags, extra...))
}

func Debug(ctx context.Context, msg string, tags []Tag, extra ...map[string]any) {
	tflog.Debug(ctx, FormatTags(tags)+" "+msg, mergeFields(tags, extra...))
}

func Trace(ctx context.Context, msg string, tags []Tag, extra ...map[string]any) {
	tflog.Trace(ctx, FormatTags(tags)+" "+msg, mergeFields(tags, extra...))
}

func Warn(ctx context.Context, msg string, tags []Tag, extra ...map[string]any) {
	tflog.Warn(ctx, FormatTags(tags)+" "+msg, mergeFields(tags, extra...))
}
