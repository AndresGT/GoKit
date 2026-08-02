package logger

import "testing"

func Test_formatFields(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		fields map[string]any
		want   string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatFields(tt.fields)
			// TODO: update the condition below to compare got with tt.want.
			if true {
				t.Errorf("formatFields() = %v, want %v", got, tt.want)
			}
		})
	}
}
