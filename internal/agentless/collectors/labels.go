package collectors

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
)

// targetMetric builds a metric whose label values come from target output.
// The target controls those bytes, and a label value that is not valid UTF-8
// makes prometheus.MustNewConstMetric panic. Such a value is replaced by its
// Go-quoted ASCII form. A valid value that starts with a double quote is quoted
// too, so a quoted form never equals another value and distinct names stay
// distinct; every other valid value is unchanged.
func targetMetric(desc *prometheus.Desc, kind prometheus.ValueType, value float64, labels ...string) prometheus.Metric {
	for i, l := range labels {
		labels[i] = targetLabel(l)
	}
	return prometheus.MustNewConstMetric(desc, kind, value, labels...)
}

func targetLabel(l string) string {
	if !utf8.ValidString(l) || strings.HasPrefix(l, `"`) {
		return strconv.QuoteToASCII(l)
	}
	return l
}
