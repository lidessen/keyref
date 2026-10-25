package wire

import (
	"errors"
	"strings"
	"testing"
)

func TestEntityIDEncodeGolden(t *testing.T) {
	tests := []struct {
		name string
		got  func() (string, error)
		want string
	}{
		{"item", func() (string, error) { return EntityIDItem(tvItem) },
			"item:" + tvItem},
		{"grant", func() (string, error) { return EntityIDGrant(tvDevice, tvItem, GrantKindUse) },
			"grant:" + tvDevice + ":" + tvItem + ":use"},
		{"device", func() (string, error) { return EntityIDDevice(tvDevice) },
			"device:" + tvDevice},
		{"directory", func() (string, error) { return EntityIDDirectory(tvVault) },
			"directory:" + tvVault},
		{"approval", func() (string, error) { return EntityIDApproval(tvItem) },
			"approval:" + tvItem},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.got()
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestEntityIDEncodeRejectsInvalidInput(t *testing.T) {
	calls := map[string]func() (string, error){
		"item short id":    func() (string, error) { return EntityIDItem("abc") },
		"device upper hex": func() (string, error) { return EntityIDDevice(strings.ToUpper(tvDevice)) },
		"grant bad kind":   func() (string, error) { return EntityIDGrant(tvDevice, tvItem, "admin") },
		"grant bad item":   func() (string, error) { return EntityIDGrant(tvDevice, "zz", GrantKindUse) },
		"directory bad id": func() (string, error) { return EntityIDDirectory("") },
		"approval bad id":  func() (string, error) { return EntityIDApproval("nothex") },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			v, err := call()
			if err == nil {
				t.Fatalf("expected error, got %q", v)
			}
		})
	}
}

func TestParseEntityIDRoundTrip(t *testing.T) {
	tests := []struct {
		entity     string
		entityID   string
		components []string
	}{
		{EntityItem, "item:" + tvItem, []string{tvItem}},
		{EntityGrant, "grant:" + tvDevice + ":" + tvItem + ":" + GrantKindView, []string{tvDevice, tvItem, GrantKindView}},
		{EntityGrant, "grant:" + tvDevice + ":" + tvItem + ":" + GrantKindUse, []string{tvDevice, tvItem, GrantKindUse}},
		{EntityDevice, "device:" + tvDevice, []string{tvDevice}},
		{EntityDirectory, "directory:" + tvVault, []string{tvVault}},
		{EntityApproval, "approval:" + tvItem, []string{tvItem}},
	}
	for _, tt := range tests {
		t.Run(tt.entityID, func(t *testing.T) {
			entity, parts, err := ParseEntityID(tt.entityID)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if entity != tt.entity {
				t.Fatalf("entity: got %q want %q", entity, tt.entity)
			}
			if len(parts) != len(tt.components) {
				t.Fatalf("components: got %v want %v", parts, tt.components)
			}
			for i := range parts {
				if parts[i] != tt.components[i] {
					t.Fatalf("component %d: got %q want %q", i, parts[i], tt.components[i])
				}
			}
		})
	}
}

func TestParseEntityIDRejectsInvalidInput(t *testing.T) {
	bad := []string{
		"",
		"item",
		"item:",
		"item:" + strings.ToUpper(tvItem),
		"item:" + tvItem + ":extra",
		"Item:" + tvItem,
		"grant:" + tvDevice + ":" + tvItem,
		"grant:" + tvDevice + ":" + tvItem + ":admin",
		"grant:" + tvDevice + ":" + tvItem + ":use:more",
		"grant:" + tvDevice + ":short:" + GrantKindUse,
		"device:" + tvVault + ":x",
		"vault:" + tvVault,
		"directory:" + tvItem + ":",
		"approval",
	}
	for _, s := range bad {
		t.Run(s, func(t *testing.T) {
			entity, parts, err := ParseEntityID(s)
			if err == nil {
				t.Fatalf("expected error, got entity %q parts %v", entity, parts)
			}
			if !errors.Is(err, ErrInvalidField) {
				t.Fatalf("error %v does not wrap ErrInvalidField", err)
			}
		})
	}
}
