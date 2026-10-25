// Typed change-log entity ids (docs/protocol.md §8.2, design §6.3): all
// identifier components are lowercase hex, so ':' never occurs inside a
// value and splitting is unambiguous.
import Foundation

public enum KeyrefEntity {
    public static let item = "item"
    public static let grant = "grant"
    public static let device = "device"
    public static let directory = "directory"
    public static let approval = "approval"
}

public enum EntityID {
    public static func item(_ itemID: String) throws -> String {
        try checkID("item_id", itemID)
        return "item:\(itemID)"
    }

    public static func grant(deviceID: String, itemID: String, kind: String) throws -> String {
        try checkID("device_id", deviceID)
        try checkID("item_id", itemID)
        guard kind == GrantKind.view || kind == GrantKind.use else {
            throw KeyrefWireError.invalidField("kind must be \"view\" or \"use\"")
        }
        return "grant:\(deviceID):\(itemID):\(kind)"
    }

    public static func device(_ deviceID: String) throws -> String {
        try checkID("device_id", deviceID)
        return "device:\(deviceID)"
    }

    public static func directory(_ vaultID: String) throws -> String {
        try checkID("vault_id", vaultID)
        return "directory:\(vaultID)"
    }

    public static func approval(_ approvalID: String) throws -> String {
        try checkID("approval_id", approvalID)
        return "approval:\(approvalID)"
    }

    /// Splits a typed entity_id into its entity kind and components
    /// (without the prefix). Unlike transcripts, entity_id strings contain
    /// only hex and enum values, so splitting on ':' is unambiguous.
    public static func parse(_ entityID: String) throws -> (entity: String, components: [String]) {
        let parts = entityID.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        func id(_ name: String, _ v: String) throws {
            guard KeyrefEncoding.isValidID(v) else {
                throw KeyrefWireError.invalidField("\(name) must be 32 lowercase hex characters")
            }
        }
        guard let head = parts.first else {
            throw KeyrefWireError.invalidField("empty entity_id")
        }
        switch head {
        case KeyrefEntity.item:
            guard parts.count == 2 else { throw KeyrefWireError.invalidField("item entity_id must be item:<item_id>") }
            try id("item_id", parts[1])
            return (KeyrefEntity.item, Array(parts[1...]))
        case KeyrefEntity.grant:
            guard parts.count == 4 else {
                throw KeyrefWireError.invalidField("grant entity_id must be grant:<device_id>:<item_id>:<kind>")
            }
            try id("device_id", parts[1])
            try id("item_id", parts[2])
            guard parts[3] == GrantKind.view || parts[3] == GrantKind.use else {
                throw KeyrefWireError.invalidField("kind must be \"view\" or \"use\"")
            }
            return (KeyrefEntity.grant, Array(parts[1...]))
        case KeyrefEntity.device:
            guard parts.count == 2 else { throw KeyrefWireError.invalidField("device entity_id must be device:<device_id>") }
            try id("device_id", parts[1])
            return (KeyrefEntity.device, Array(parts[1...]))
        case KeyrefEntity.directory:
            guard parts.count == 2 else { throw KeyrefWireError.invalidField("directory entity_id must be directory:<vault_id>") }
            try id("vault_id", parts[1])
            return (KeyrefEntity.directory, Array(parts[1...]))
        case KeyrefEntity.approval:
            guard parts.count == 2 else { throw KeyrefWireError.invalidField("approval entity_id must be approval:<approval_id>") }
            try id("approval_id", parts[1])
            return (KeyrefEntity.approval, Array(parts[1...]))
        default:
            throw KeyrefWireError.invalidField("unknown entity prefix")
        }
    }

    private static func checkID(_ name: String, _ v: String) throws {
        guard KeyrefEncoding.isValidID(v) else {
            throw KeyrefWireError.invalidField("\(name) must be 32 lowercase hex characters")
        }
    }
}
