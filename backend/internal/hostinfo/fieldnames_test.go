package hostinfo

import (
	"reflect"
	"strings"
)

func fieldNames(v any) string {
	t := reflect.TypeOf(v)
	var n []string
	for i := 0; i < t.NumField(); i++ {
		n = append(n, t.Field(i).Name)
	}
	return strings.Join(n, " ")
}
