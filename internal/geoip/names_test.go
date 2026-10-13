package geoip

import "testing"

func TestNames(t *testing.T) {
	t.Parallel()
	// ISO 3166-1 currently has 249 officially assigned codes; Kosovo (XK) is
	// a user-assigned code that every GeoIP vendor emits anyway.
	if got := len(names); got < 249 {
		t.Errorf("names has %d entries; want >= 249", got)
	}
	tests := []struct {
		code string
		want string
	}{
		{"US", "United States"},
		{"us", "United States"},
		{"GB", "United Kingdom"},
		{"DE", "Germany"},
		{"XK", "Kosovo"},
		{"ZZ", ""},
		{"", ""},
		{"USA", ""},
	}
	for _, tc := range tests {
		if got := Name(tc.code); got != tc.want {
			t.Errorf("Name(%q) = %q; want %q", tc.code, got, tc.want)
		}
	}
	for code, name := range names {
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
			t.Errorf("names key %q is not two upper-case ASCII letters", code)
		}
		if name == "" {
			t.Errorf("names[%q] is empty", code)
		}
	}
}

func TestFlag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code string
		want string
	}{
		{"US", "\U0001F1FA\U0001F1F8"},
		{"de", "\U0001F1E9\U0001F1EA"},
		{"", ""},
		{"USA", ""},
		{"1A", ""},
		{"U", ""},
		{"ÜS", ""},
	}
	for _, tc := range tests {
		if got := Flag(tc.code); got != tc.want {
			t.Errorf("Flag(%q) = %q; want %q", tc.code, got, tc.want)
		}
	}
}
