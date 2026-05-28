package logging

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
)

func DiagError(err *EAAError) diag.Diagnostics {
	return diag.Diagnostics{
		diag.Diagnostic{
			Severity: diag.Error,
			Summary:  err.Error(),
		},
	}
}

func DiagWarning(err *EAAError) diag.Diagnostics {
	return diag.Diagnostics{
		diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  err.Error(),
		},
	}
}

func DiagErrorf(tags []Tag, format string, args ...any) diag.Diagnostics {
	return DiagError(Errorf(tags, format, args...))
}

func DiagWarningf(tags []Tag, format string, args ...any) diag.Diagnostics {
	return DiagWarning(Errorf(tags, format, args...))
}

func DiagFromErr(err error, tags []Tag, msg string) diag.Diagnostics {
	return DiagError(Wrapf(err, tags, "%s", msg))
}

func DiagFromErrf(err error, tags []Tag, format string, args ...any) diag.Diagnostics {
	return DiagError(Wrapf(err, tags, "%s", fmt.Sprintf(format, args...)))
}
