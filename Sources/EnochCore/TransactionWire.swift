// TransactionWire — JSON wire shape accepted by `POST /v1/submit_tx`.
//
// Matches the operator's submitTxRequestJSON byte-for-byte: hex strings
// for all binary fields, snake_case keys. This file deliberately keeps
// wire types separate from the domain `Transaction` — Codable on the
// domain types would obscure the hex/order dance and lock us into a
// specific encoding decision.

import Foundation

/// JSON wrapper for `POST /v1/submit_tx`. Fields mirror the operator's
/// submitTxRequestJSON; `tx_hash` and `script_*` are hex strings; the
/// `tx_hash` value uses display order (the form `bitcoin-cli` shows).
public struct SubmitTxRequest: Codable, Equatable {
    public var version: UInt32
    public var inputs: [TxInputWire]
    public var outputs: [TxOutputWire]
    public var lockTime: UInt32

    enum CodingKeys: String, CodingKey {
        case version
        case inputs
        case outputs
        case lockTime = "lock_time"
    }
}

public struct TxInputWire: Codable, Equatable {
    public var txHash: String
    public var vout: UInt32
    public var scriptSig: String
    public var sequence: UInt32

    enum CodingKeys: String, CodingKey {
        case txHash = "tx_hash"
        case vout
        case scriptSig = "script_sig"
        case sequence
    }
}

public struct TxOutputWire: Codable, Equatable {
    public var amount: UInt64
    public var scriptPubKey: String

    enum CodingKeys: String, CodingKey {
        case amount
        case scriptPubKey = "script_pubkey"
    }
}

// MARK: - Domain ↔ wire

public extension Transaction {
    /// Convert to the JSON wire shape POST /v1/submit_tx accepts.
    func toWire() -> SubmitTxRequest {
        SubmitTxRequest(
            version: version,
            inputs: inputs.map {
                TxInputWire(
                    txHash: $0.txHash.hexString,
                    vout: $0.vout,
                    scriptSig: $0.scriptSig.hexString,
                    sequence: $0.sequence
                )
            },
            outputs: outputs.map {
                TxOutputWire(
                    amount: $0.amount,
                    scriptPubKey: $0.scriptPubKey.hexString
                )
            },
            lockTime: lockTime
        )
    }

    /// Decode an inbound wire shape (e.g. when replaying a tx body
    /// stored in operator tx-history).
    init(wire req: SubmitTxRequest) throws {
        self.version = req.version
        self.lockTime = req.lockTime
        self.inputs = try req.inputs.map {
            TxInput(
                txHash: try Data(hex: $0.txHash),
                vout: $0.vout,
                scriptSig: try Data(hex: $0.scriptSig),
                sequence: $0.sequence
            )
        }
        self.outputs = try req.outputs.map {
            TxOutput(
                amount: $0.amount,
                scriptPubKey: try Data(hex: $0.scriptPubKey)
            )
        }
    }
}

// MARK: - Hex helpers

public enum HexError: Swift.Error, Equatable {
    case oddLength
    case nonHexCharacter(Character)
}

public extension Data {
    /// Lowercase hex string — what the operator emits and accepts.
    var hexString: String {
        var s = String()
        s.reserveCapacity(count * 2)
        for byte in self {
            s.append(hexNibble(byte >> 4))
            s.append(hexNibble(byte & 0x0F))
        }
        return s
    }

    /// Decode a hex string. Empty string is the empty `Data`. Odd
    /// length and non-hex characters surface as `HexError` rather
    /// than producing silently-truncated bytes.
    init(hex: String) throws {
        if hex.isEmpty {
            self = Data()
            return
        }
        guard hex.count % 2 == 0 else { throw HexError.oddLength }
        var out = Data(capacity: hex.count / 2)
        var iter = hex.makeIterator()
        while let hi = iter.next(), let lo = iter.next() {
            guard let h = nibbleValue(hi), let l = nibbleValue(lo) else {
                throw HexError.nonHexCharacter(hi)
            }
            out.append((h << 4) | l)
        }
        self = out
    }
}

private func hexNibble(_ v: UInt8) -> Character {
    let digits: [Character] = [
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "a", "b", "c", "d", "e", "f",
    ]
    return digits[Int(v & 0x0F)]
}

private func nibbleValue(_ c: Character) -> UInt8? {
    switch c {
    case "0"..."9": return UInt8(c.asciiValue! - Character("0").asciiValue!)
    case "a"..."f": return UInt8(c.asciiValue! - Character("a").asciiValue! + 10)
    case "A"..."F": return UInt8(c.asciiValue! - Character("A").asciiValue! + 10)
    default: return nil
    }
}
