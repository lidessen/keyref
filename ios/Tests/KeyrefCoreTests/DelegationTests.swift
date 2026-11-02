// Auto-approval delegation wire contract (docs/protocol.md §3.10, §6.31,
// design v0.8 §14.8).
//
// The byte-level anchors here are produced by the Go implementation
// (proto/wire BuildDelegationTranscript + encoding/json), so a Swift
// drift in the transcript layout or the policy's key order fails this
// file before it fails a cross-language test.
import XCTest

@testable import KeyrefCore

final class DelegationTests: XCTestCase {
    private let vaultID = "00112233445566778899aabbccddeeff"
    private let otherVaultID = "11111111111111111111111111111111"
    private let cliID = "0123456789abcdef0123456789abcdef"

    // MARK: policy encoding (byte-stable, §3.10)

    func testPolicyEncodingMatchesDocumentedJSON() throws {
        let p = KeyrefDelegationPolicy(
            senders: ["10086", "95533"], maxAgeMin: 5,
            perCLIHourly: 10, perCLIDaily: 50, cliDevices: [cliID])
        let expected = "{\"v\":1,\"senders\":[\"10086\",\"95533\"],"
            + "\"max_age_min\":5,\"per_cli_hourly\":10,\"per_cli_daily\":50,"
            + "\"cli_devices\":[\"" + cliID + "\"]}"
        XCTAssertEqual(try p.encodedJSONString(), expected)
        // Same bytes every time — the transcript carries them verbatim.
        XCTAssertEqual(try p.encodedJSONString(), try p.encodedJSONString())
    }

    func testPolicyEncodingOmitsEmptyFields() throws {
        // The revocation form is exactly {"v":1} — no null, no empty
        // arrays, no zero limits.
        XCTAssertEqual(try KeyrefDelegationPolicy.revocation.encodedJSONString(),
                       #"{"v":1}"#)
        // Zeros and empties drop out; the key order stays fixed.
        let partial = KeyrefDelegationPolicy(senders: ["10086"],
                                             perCLIDaily: 50)
        XCTAssertEqual(try partial.encodedJSONString(),
                       #"{"v":1,"senders":["10086"],"per_cli_daily":50}"#)
        // cli_devices alone still lands after the limits.
        let onlyCLI = KeyrefDelegationPolicy(cliDevices: [cliID])
        XCTAssertEqual(try onlyCLI.encodedJSONString(),
                       "{\"v\":1,\"cli_devices\":[\"" + cliID + "\"]}")
    }

    func testPolicyEncodingEscapesLikeGo() throws {
        // Go's json.Marshal HTML-escapes < > & and quotes controls; a
        // sender is validated only on length, so this must match too.
        let p = KeyrefDelegationPolicy(senders: ["a<b>c&d", "x\ty"])
        XCTAssertEqual(try p.encodedJSONString(),
                       #"{"v":1,"senders":["a\u003cb\u003ec\u0026d","x\ty"]}"#)
    }

    func testPolicyEncodeDecodeRoundtrip() throws {
        let p = KeyrefDelegationPolicy(
            senders: ["10086"], maxAgeMin: 5, perCLIHourly: 10,
            perCLIDaily: 50, cliDevices: [cliID])
        let json = try p.encodedJSONString()
        XCTAssertEqual(try KeyrefDelegationPolicy.decode(json: json), p)
        // Re-encoding the decoded value reproduces the same bytes.
        XCTAssertEqual(try KeyrefDelegationPolicy.decode(json: json).encodedJSONString(),
                       json)
    }

    // MARK: strict decoding

    func testStrictDecodingRejectsUnknownField() {
        // The decider rejects the whole policy if it sees a key it does
        // not know — a half-understood policy must never read as wider.
        XCTAssertThrowsError(
            try KeyrefDelegationPolicy.decode(json: #"{"v":1,"nope":true}"#)) { error in
            guard let wire = error as? KeyrefWireError,
                  case .invalidField(let msg) = wire else {
                return XCTFail("wrong error type: \(error)")
            }
            XCTAssertTrue(msg.contains("unknown field"), msg)
        }
        XCTAssertThrowsError(
            try KeyrefDelegationPolicy.decode(
                json: #"{"v":1,"senders":["10086"],"decider_api":"https://x"}"#))
        // Unknown key is caught before anything else is trusted.
        XCTAssertThrowsError(
            try KeyrefDelegationPolicy.decode(json: #"{"v":2,"nope":1}"#))
    }

    func testPolicyDecodingRejectsBadFields() {
        XCTAssertThrowsError(try KeyrefDelegationPolicy.decode(json: #"{"v":2}"#),
                             "v must be 1")
        XCTAssertThrowsError(try KeyrefDelegationPolicy.decode(json: #"{}"#),
                             "missing v")
        // An explicitly empty senders array is the revocation form, not
        // an error — same as Go.
        XCTAssertNoThrow(try KeyrefDelegationPolicy.decode(
            json: #"{"v":1,"senders":[]}"#).encodedJSONString())
        // Empty sender string (Go: 1..64 bytes).
        XCTAssertThrowsError(
            try KeyrefDelegationPolicy.decode(json: #"{"v":1,"senders":[""]}"#))
        XCTAssertThrowsError(
            try KeyrefDelegationPolicy.decode(
                json: #"{"v":1,"senders":["# + String(repeating: "9", count: 65) + #"]}"#))
        // cli_devices must be 32 lowercase hex.
        XCTAssertThrowsError(
            try KeyrefDelegationPolicy.decode(
                json: #"{"v":1,"cli_devices":["ABCDEF0123456789abcdef0123456789"]}"#))
        XCTAssertThrowsError(
            try KeyrefDelegationPolicy.decode(
                json: #"{"v":1,"cli_devices":["short"]}"#))
        // Negative limits.
        XCTAssertThrowsError(
            try KeyrefDelegationPolicy.decode(json: #"{"v":1,"max_age_min":-1}"#))
        XCTAssertThrowsError(
            try KeyrefDelegationPolicy.decode(json: #"{"v":1,"per_cli_hourly":-1}"#))
        XCTAssertThrowsError(
            try KeyrefDelegationPolicy.decode(json: #"{"v":1,"per_cli_daily":-1}"#))
        // Not an object at all.
        XCTAssertThrowsError(try KeyrefDelegationPolicy.decode(json: #"[1,2]"#))
        XCTAssertThrowsError(try KeyrefDelegationPolicy.decode(json: "not json"))
    }

    func testEmptyPolicyIsRevocation() throws {
        let empty = try KeyrefDelegationPolicy.decode(json: #"{"v":1}"#)
        XCTAssertTrue(empty.isEmpty)
        XCTAssertTrue(empty.isRevocation)
        XCTAssertEqual(empty, .revocation)
        // Nothing can ever be auto-approved without a sender allowlist…
        XCTAssertFalse(empty.allowsSender("10086"))
        // …and the revocation form re-encodes to exactly itself.
        XCTAssertEqual(try empty.encodedJSONString(), #"{"v":1}"#)

        let active = KeyrefDelegationPolicy(senders: ["10086"])
        XCTAssertFalse(active.isEmpty)
        XCTAssertFalse(active.isRevocation)
    }

    func testAllowsSenderIsByteExactAndEmptyCLIDevicesIsUnrestricted() throws {
        let p = KeyrefDelegationPolicy(senders: ["10086"], cliDevices: [cliID])
        XCTAssertTrue(p.allowsSender("10086"))
        XCTAssertFalse(p.allowsSender("+8610086"), "no prefix matching")
        XCTAssertTrue(p.allowsCLI(cliID))
        XCTAssertFalse(p.allowsCLI("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
        // Empty list = no restriction (still gated by the sender list).
        let open = KeyrefDelegationPolicy(senders: ["10086"])
        XCTAssertTrue(open.allowsCLI("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    }

    // MARK: transcript (§3.10)

    func testTranscriptRoundtrip() throws {
        let policy = KeyrefDelegationPolicy(
            senders: ["10086"], maxAgeMin: 5, perCLIHourly: 10,
            perCLIDaily: 50, cliDevices: [cliID])
        let t = KeyrefDelegationTranscript(
            vaultID: vaultID, delegationRevision: 7,
            policyJSON: try policy.encodedJSONString())
        let bytes = try t.buildBytes()
        XCTAssertTrue(bytes.starts(with: Data("KEYREF1\u{00}delegation\u{00}".utf8)))
        let parsed = try KeyrefDelegationTranscript.parse(bytes, wantVaultID: vaultID)
        XCTAssertEqual(parsed, t)
        // Rebuild-and-compare: building the parsed form gives the same
        // bytes back, which is what a verifier actually checks.
        XCTAssertEqual(try parsed.buildBytes(), bytes)
        // The policy inside still decodes.
        XCTAssertEqual(try KeyrefDelegationPolicy.decode(json: parsed.policyJSON),
                       policy)
    }

    func testTranscriptRejectsWrongVault() throws {
        let t = KeyrefDelegationTranscript(
            vaultID: vaultID, delegationRevision: 3,
            policyJSON: #"{"v":1}"#)
        let bytes = try t.buildBytes()
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript.parse(bytes, wantVaultID: otherVaultID),
            "a transcript naming another vault is rejected")
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript.parse(bytes, wantVaultID: "not-an-id"))
    }

    func testTranscriptRevisionOrdering() throws {
        func bytes(_ rev: UInt64) throws -> Data {
            try KeyrefDelegationTranscript(vaultID: vaultID,
                                           delegationRevision: rev,
                                           policyJSON: #"{"v":1}"#).buildBytes()
        }
        // Parse reports the revision the u64be field actually holds.
        for rev: UInt64 in [1, 2, 3, 255, 256, 1 << 32, .max] {
            let parsed = try KeyrefDelegationTranscript.parse(try bytes(rev),
                                                              wantVaultID: vaultID)
            XCTAssertEqual(parsed.delegationRevision, rev)
        }
        // Distinct revisions give distinct bytes (the PUT ladder is
        // "strictly greater", so the wire must actually differ).
        XCTAssertNotEqual(try bytes(1), try bytes(2))
        // The revision sits at a fixed offset, 8 bytes wide, big-endian.
        let b = try bytes(3)
        let revOffset = "KEYREF1\u{00}delegation\u{00}".utf8.count + vaultID.utf8.count + 1
        XCTAssertEqual(Array(b[b.startIndex + revOffset ..< b.startIndex + revOffset + 8]),
                       [0, 0, 0, 0, 0, 0, 0, 3])
        // The revision itself is covered by the signature, not by the
        // rebuild — rewriting it to another well-formed number still
        // round-trips, which is exactly why the decider must verify the
        // signature before trusting the revision. What the rebuild does
        // catch is anything that breaks the fixed layout or the policy's
        // bytes: the separator after the revision, and any byte the
        // builder would not reproduce verbatim.
        var sep = b
        sep[sep.startIndex + revOffset + 8] = 0x01
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript.parse(sep, wantVaultID: vaultID),
            "a broken separator fails the rebuild-and-compare")
        // A non-UTF-8 policy byte cannot survive the round trip: the
        // parse turns it into U+FFFD, so the rebuild differs.
        var invalidUTF8 = b
        invalidUTF8[invalidUTF8.endIndex - 1] = 0xFF
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript.parse(invalidUTF8, wantVaultID: vaultID),
            "a non-UTF-8 policy byte fails the rebuild-and-compare")
        // Truncating inside the revision field fails structurally.
        let truncated = Data(b.prefix(revOffset + 6))
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript.parse(truncated, wantVaultID: vaultID))
        // Cutting the whole policy away leaves nothing for the builder's
        // 1..16384 rule to accept.
        let cutPolicy = Data(b.prefix(b.count - 7))
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript.parse(cutPolicy, wantVaultID: vaultID))
    }

    func testTranscriptRejectsBadFields() throws {
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript(vaultID: "xyz", delegationRevision: 1,
                                           policyJSON: #"{"v":1}"#).buildBytes())
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript(vaultID: vaultID, delegationRevision: 1,
                                           policyJSON: "").buildBytes(),
            "empty policy_json")
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript(
                vaultID: vaultID, delegationRevision: 1,
                policyJSON: String(repeating: "x",
                                   count: KeyrefDelegationTranscript.policyMaxBytes + 1)
            ).buildBytes(), "policy over the 16 KiB cap")
        // Garbage inputs to the parser.
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript.parse(Data(), wantVaultID: vaultID))
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript.parse(Data("KEYREF1".utf8),
                                                 wantVaultID: vaultID))
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript.parse(
                Data("KEYREF1\u{00}delegation\u{00}nosplit".utf8),
                wantVaultID: vaultID), "no NUL after the prefix")
        // Structural damage: the separator between the revision and the
        // policy is not a byte the rebuild will reproduce.
        let good = try KeyrefDelegationTranscript(
            vaultID: vaultID, delegationRevision: 1,
            policyJSON: #"{"v":1}"#).buildBytes()
        var mangled = good
        mangled[mangled.endIndex - 8] = 0x01
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript.parse(mangled, wantVaultID: vaultID))
        // A policy byte that cannot round-trip through a Swift String
        // (invalid UTF-8) fails the rebuild-and-compare.
        var badUTF8 = good
        badUTF8[badUTF8.endIndex - 1] = 0xFF
        XCTAssertThrowsError(
            try KeyrefDelegationTranscript.parse(badUTF8, wantVaultID: vaultID))
    }

    // MARK: exact bytes (Go cross-check)

    func testTranscriptExactBytesAgainstGo() throws {
        // Built by proto/wire BuildDelegationTranscript:
        //   vault 00112233445566778899aabbccddeeff, revision 3,
        //   policy {"v":1,"senders":["10086"],"max_age_min":5,
        //           "per_cli_hourly":10,"per_cli_daily":50,
        //           "cli_devices":["0123456789abcdef0123456789abcdef"]}
        let expectedHex =
            "4b4559524546310064656c65676174696f6e003030313132323333343435353636373738383939616162626363646465656666000000000000000003007b2276223a312c2273656e64657273223a5b223130303836225d2c226d61785f6167655f6d696e223a352c227065725f636c695f686f75726c79223a31302c227065725f636c695f6461696c79223a35302c22636c695f64657669636573223a5b223031323334353637383961626364656630313233343536373839616263646566225d7d"
        let policy = KeyrefDelegationPolicy(
            senders: ["10086"], maxAgeMin: 5, perCLIHourly: 10,
            perCLIDaily: 50, cliDevices: [cliID])
        let t = KeyrefDelegationTranscript(
            vaultID: vaultID, delegationRevision: 3,
            policyJSON: try policy.encodedJSONString())
        XCTAssertEqual(KeyrefEncoding.hexEncode(try t.buildBytes()), expectedHex)
        // …and it parses back to the same structure.
        let parsed = try KeyrefDelegationTranscript.parse(
            try KeyrefEncoding.hexDecode(expectedHex), wantVaultID: vaultID)
        XCTAssertEqual(parsed.delegationRevision, 3)
        XCTAssertEqual(parsed.policyJSON, try policy.encodedJSONString())
    }

    func testRevocationTranscriptExactBytesAgainstGo() throws {
        // vault 00112233445566778899aabbccddeeff, revision 1,
        // policy {"v":1}.
        let expectedHex =
            "4b4559524546310064656c65676174696f6e003030313132323333343435353636373738383939616162626363646465656666000000000000000001007b2276223a317d"
        let t = KeyrefDelegationTranscript(
            vaultID: vaultID, delegationRevision: 1,
            policyJSON: #"{"v":1}"#)
        XCTAssertEqual(KeyrefEncoding.hexEncode(try t.buildBytes()), expectedHex)
        let parsed = try KeyrefDelegationTranscript.parse(
            try KeyrefEncoding.hexDecode(expectedHex), wantVaultID: vaultID)
        XCTAssertEqual(parsed.delegationRevision, 1)
        XCTAssertEqual(parsed.policyJSON, #"{"v":1}"#)
        XCTAssertTrue(try KeyrefDelegationPolicy.decode(json: parsed.policyJSON).isRevocation)
    }

    // MARK: wire shapes

    func testDelegationWireShapes() throws {
        // PUT body keys, exactly as §6.31 spells them.
        let req = DelegationPutRequest(delegationRevision: 3,
                                       delegationSigned: Data([1, 2]),
                                       signature: Data([3]))
        let encoded = try WireJSON.encoder.encode(req)
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        XCTAssertEqual(Set(obj.keys),
                       ["delegation_revision", "delegation_signed", "signature"])
        XCTAssertEqual(obj["delegation_revision"] as? Int, 3)
        XCTAssertEqual(obj["delegation_signed"] as? String, "AQI=")

        // GET accepts both spellings of "no delegation": the protocol's
        // null and Go Blob's "" for a nil slice.
        let nullBody = Data(#"{"delegation_revision":0,"delegation_signed":null,"signature":null}"#.utf8)
        let fromNull = try WireJSON.decoder.decode(DelegationGetResponse.self, from: nullBody)
        XCTAssertEqual(fromNull.delegationRevision, 0)
        XCTAssertNil(fromNull.delegationSigned)

        let emptyBody = Data(#"{"delegation_revision":0,"delegation_signed":"","signature":""}"#.utf8)
        let fromEmpty = try WireJSON.decoder.decode(DelegationGetResponse.self, from: emptyBody)
        XCTAssertEqual(fromEmpty.delegationRevision, 0)
        XCTAssertTrue(fromEmpty.delegationSigned?.isEmpty ?? true)

        // A populated response round-trips through the shared coder.
        let full = DelegationGetResponse(delegationRevision: 3,
                                         delegationSigned: Data([9, 9]),
                                         signature: Data([8]))
        let back = try WireJSON.decoder.decode(
            DelegationGetResponse.self, from: try WireJSON.encoder.encode(full))
        XCTAssertEqual(back, full)
    }
}
