package wire

import (
	"fmt"
	"strings"
)

// Change-log entity kinds and entity_id prefixes (protocol §8.2, design
// §6.3). All identifier components are lowercase hex, so ':' never
// occurs inside a value.
const (
	EntityItem      = "item"
	EntityGrant     = "grant"
	EntityDevice    = "device"
	EntityDirectory = "directory"
	EntityApproval  = "approval"
)

// EntityIDItem encodes "item:<item_id>".
func EntityIDItem(itemID string) (string, error) {
	if err := requireID("item_id", itemID); err != nil {
		return "", err
	}
	return EntityItem + ":" + itemID, nil
}

// EntityIDGrant encodes "grant:<device_id>:<item_id>:<kind>".
func EntityIDGrant(deviceID, itemID, kind string) (string, error) {
	for _, f := range []struct{ name, id string }{
		{"device_id", deviceID},
		{"item_id", itemID},
	} {
		if err := requireID(f.name, f.id); err != nil {
			return "", err
		}
	}
	if err := requireGrantKind(kind); err != nil {
		return "", err
	}
	return EntityGrant + ":" + deviceID + ":" + itemID + ":" + kind, nil
}

// EntityIDDevice encodes "device:<device_id>".
func EntityIDDevice(deviceID string) (string, error) {
	if err := requireID("device_id", deviceID); err != nil {
		return "", err
	}
	return EntityDevice + ":" + deviceID, nil
}

// EntityIDDirectory encodes "directory:<vault_id>".
func EntityIDDirectory(vaultID string) (string, error) {
	if err := requireID("vault_id", vaultID); err != nil {
		return "", err
	}
	return EntityDirectory + ":" + vaultID, nil
}

// EntityIDApproval encodes "approval:<approval_id>".
func EntityIDApproval(approvalID string) (string, error) {
	if err := requireID("approval_id", approvalID); err != nil {
		return "", err
	}
	return EntityApproval + ":" + approvalID, nil
}

// ParseEntityID validates a typed entity_id string and splits it into
// its entity kind and identifier components (without the prefix): item
// and directory yield one component, grant yields device_id, item_id and
// kind. Unlike transcripts, entity_id strings contain only hex and enum
// values, so splitting on ':' is unambiguous here.
func ParseEntityID(entityID string) (entity string, components []string, err error) {
	parts := strings.Split(entityID, ":")
	require := func(n int) bool { return len(parts) == n }
	checkID := func(name, v string) error {
		if !ValidID(v) {
			return fmt.Errorf("%w: %s must be 32 lowercase hex characters", ErrInvalidField, name)
		}
		return nil
	}
	switch parts[0] {
	case EntityItem:
		if !require(2) {
			return "", nil, fmt.Errorf("%w: item entity_id must be item:<item_id>", ErrInvalidField)
		}
		if err := checkID("item_id", parts[1]); err != nil {
			return "", nil, err
		}
		return EntityItem, parts[1:], nil
	case EntityGrant:
		if !require(4) {
			return "", nil, fmt.Errorf("%w: grant entity_id must be grant:<device_id>:<item_id>:<kind>", ErrInvalidField)
		}
		if err := checkID("device_id", parts[1]); err != nil {
			return "", nil, err
		}
		if err := checkID("item_id", parts[2]); err != nil {
			return "", nil, err
		}
		if err := requireGrantKind(parts[3]); err != nil {
			return "", nil, err
		}
		return EntityGrant, parts[1:], nil
	case EntityDevice:
		if !require(2) {
			return "", nil, fmt.Errorf("%w: device entity_id must be device:<device_id>", ErrInvalidField)
		}
		if err := checkID("device_id", parts[1]); err != nil {
			return "", nil, err
		}
		return EntityDevice, parts[1:], nil
	case EntityDirectory:
		if !require(2) {
			return "", nil, fmt.Errorf("%w: directory entity_id must be directory:<vault_id>", ErrInvalidField)
		}
		if err := checkID("vault_id", parts[1]); err != nil {
			return "", nil, err
		}
		return EntityDirectory, parts[1:], nil
	case EntityApproval:
		if !require(2) {
			return "", nil, fmt.Errorf("%w: approval entity_id must be approval:<approval_id>", ErrInvalidField)
		}
		if err := checkID("approval_id", parts[1]); err != nil {
			return "", nil, err
		}
		return EntityApproval, parts[1:], nil
	default:
		return "", nil, fmt.Errorf("%w: unknown entity prefix", ErrInvalidField)
	}
}
