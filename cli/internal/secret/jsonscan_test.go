package secret

import (
	"bytes"
	"errors"
	"testing"
)

func extract(t *testing.T, doc, field string) ([]byte, error) {
	t.Helper()
	buf, err := ExtractStringField([]byte(doc), field)
	if err != nil {
		return nil, err
	}
	t.Cleanup(buf.Destroy)
	return buf.Bytes(), nil
}

func TestExtractStringField(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"plain value first", `{"v":1,"value":"sk-plain","username":"u"}`, "sk-plain"},
		{"value after nested structures", `{"v":1,"fields":{"k":["a",2,true,null]},"value":"after","notes":""}`, "after"},
		{"escapes", `{"v":1,"value":"a\nb\tc\"d\\e\/f","username":""}`, "a\nb\tc\"d\\e/f"},
		{"unicode escapes", `{"value":"\u0041\u00e9\u4e2d"}`, "Aé中"},
		{"surrogate pair emoji", `{"value":"\ud83d\ude00"}`, "😀"},
		{"empty string", `{"value":""}`, ""},
		{"whitespace tolerance", "{\n\t\"v\"  :\t 1 ,\n \"value\" : \"x\"\n}", "x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := extract(t, c.doc, "value")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, []byte(c.want)) {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestExtractStringFieldOtherFields(t *testing.T) {
	// Fields that matter to the product besides value.
	for _, field := range []string{"username", "notes"} {
		got, err := extract(t, `{"value":"v","`+field+`":"n","notes":"x"}`, field)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, []byte("n")) {
			t.Fatalf("field %s: got %q", field, got)
		}
	}
}

func TestExtractStringFieldErrors(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want error
	}{
		{"missing field", `{"v":1,"username":"u"}`, ErrFieldNotFound},
		{"empty object", `{}`, ErrFieldNotFound},
		{"field is a number", `{"value":42}`, ErrNotAString},
		{"field is an object", `{"value":{"x":1}}`, ErrNotAString},
		{"malformed json", `{"value":`, ErrSyntax},
		{"unterminated string", `{"value":"abc`, ErrSyntax},
		{"bad escape", `{"value":"a\qb"}`, ErrSyntax},
		{"lone surrogate", `{"value":"\ud83d"}`, ErrSyntax},
		{"not an object", `["value"]`, ErrSyntax},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ExtractStringField([]byte(c.doc), "value")
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
	if _, err := ExtractStringField([]byte(`{}`), ""); err == nil {
		t.Fatal("empty field name accepted")
	}
}

func TestExtractStringFieldLargeValue(t *testing.T) {
	// Secrets may be up to 64 KiB (design §2.1).
	want := bytes.Repeat([]byte("z"), 64*1024)
	doc := append([]byte(`{"v":1,"value":"`), want...)
	doc = append(doc, '"', '}')
	got, err := extract(t, string(doc), "value")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("large value mismatch: got %d bytes", len(got))
	}
}
