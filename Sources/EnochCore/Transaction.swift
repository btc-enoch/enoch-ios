// Transaction — Swift mirror of operator/ledger.Transaction.
//
// Two layers:
//   - Domain types (this file): Data fields, type-safe; what the
//     wallet builds, hashes, and signs against.
//   - Wire types (TransactionWire.swift): Codable, hex strings;
//     what `POST /v1/submit_tx` accepts.
//
// Wire serialization (Bitcoin canonical format, mirrors operator's
// WireBytes) plus the legacy P2PKH SIGHASH_ALL sighash live here.
// Both must be byte-exact with the operator side — a one-bit drift
// in either produces signatures that look valid but verify to false.

import Foundation

public struct Transaction: Equatable {
    public var version: UInt32
    public var inputs: [TxInput]
    public var outputs: [TxOutput]
    public var lockTime: UInt32

    public init(version: UInt32, inputs: [TxInput], outputs: [TxOutput], lockTime: UInt32) {
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.lockTime = lockTime
    }
}

public struct TxInput: Equatable {
    /// 32 bytes in DISPLAY order (the form `bitcoin-cli` prints,
    /// matching the operator's storage). Bitcoin wire serialization
    /// reverses these bytes — handled inside `wireBytes()`.
    public var txHash: Data
    public var vout: UInt32
    public var scriptSig: Data
    public var sequence: UInt32

    public init(txHash: Data, vout: UInt32, scriptSig: Data = Data(), sequence: UInt32 = 0xFFFFFFFF) {
        self.txHash = txHash
        self.vout = vout
        self.scriptSig = scriptSig
        self.sequence = sequence
    }
}

public struct TxOutput: Equatable {
    public var amount: UInt64
    public var scriptPubKey: Data

    public init(amount: UInt64, scriptPubKey: Data) {
        self.amount = amount
        self.scriptPubKey = scriptPubKey
    }
}

public enum TransactionError: Swift.Error, Equatable {
    case wrongTxHashLength(input: Int, length: Int)
    case inputIndexOutOfRange(Int)
}

public extension Transaction {
    /// Bitcoin canonical wire serialization. Format:
    ///
    ///   [4]    version (LE uint32)
    ///   varint #inputs
    ///   per input:
    ///     [32]   prev tx hash, REVERSED from display order
    ///     [4]    vout (LE uint32)
    ///     varint scriptSig length
    ///     [..]   scriptSig
    ///     [4]    sequence (LE uint32)
    ///   varint #outputs
    ///   per output:
    ///     [8]    amount (LE uint64)
    ///     varint scriptPubKey length
    ///     [..]   scriptPubKey
    ///   [4]    lockTime (LE uint32)
    ///
    /// Mirrors operator/ledger/script.go::WireBytes byte for byte.
    func wireBytes() throws -> Data {
        var out = Data()
        out.appendUInt32LE(version)

        out.appendVarInt(UInt64(inputs.count))
        for (i, input) in inputs.enumerated() {
            guard input.txHash.count == 32 else {
                throw TransactionError.wrongTxHashLength(input: i, length: input.txHash.count)
            }
            // Reverse display order → wire order.
            out.append(contentsOf: input.txHash.reversed())
            out.appendUInt32LE(input.vout)
            out.appendVarInt(UInt64(input.scriptSig.count))
            out.append(input.scriptSig)
            out.appendUInt32LE(input.sequence)
        }

        out.appendVarInt(UInt64(outputs.count))
        for output in outputs {
            out.appendUInt64LE(output.amount)
            out.appendVarInt(UInt64(output.scriptPubKey.count))
            out.append(output.scriptPubKey)
        }

        out.appendUInt32LE(lockTime)
        return out
    }

    /// L2 transaction id — double-SHA256 over the wire bytes with
    /// every scriptSig zeroed. Same construction as Bitcoin's txid:
    /// excluding scriptSigs makes the id immune to signature
    /// malleability. Returned in NATURAL order (display order is
    /// `Data(txHash().reversed())`).
    func txHash() throws -> Data {
        var stripped = self
        stripped.inputs = inputs.map {
            TxInput(txHash: $0.txHash, vout: $0.vout, scriptSig: Data(), sequence: $0.sequence)
        }
        let bytes = try stripped.wireBytes()
        return Hashing.hash256(bytes)
    }

    /// Legacy P2PKH SIGHASH_ALL sighash for input `inputIndex`.
    ///
    /// Algorithm (matches btcsuite/btcd/txscript.CalcSignatureHash
    /// for SIGHASH_ALL on a non-segwit input):
    ///
    ///   1. Copy the tx.
    ///   2. Zero every input's scriptSig.
    ///   3. Set input[inputIndex].scriptSig = prevScriptPubKey.
    ///   4. Serialize via wireBytes().
    ///   5. Append 4-byte LE sighash type (0x01000000 for SIGHASH_ALL).
    ///   6. Double-SHA256.
    ///
    /// `prevScriptPubKey` is the script of the UTXO being spent — the
    /// wallet gets it from `/v1/utxos/{addr}` before signing.
    func sighashLegacyAll(inputIndex: Int, prevScriptPubKey: Data) throws -> Data {
        guard inputs.indices.contains(inputIndex) else {
            throw TransactionError.inputIndexOutOfRange(inputIndex)
        }
        var modified = self
        modified.inputs = inputs.enumerated().map { (i, input) in
            let script = (i == inputIndex) ? prevScriptPubKey : Data()
            return TxInput(txHash: input.txHash, vout: input.vout, scriptSig: script, sequence: input.sequence)
        }
        var serialized = try modified.wireBytes()
        // SIGHASH_ALL = 0x01, expressed as 4-byte LE = 01 00 00 00.
        serialized.appendUInt32LE(0x00000001)
        return Hashing.hash256(serialized)
    }
}

// MARK: - Bitcoin little-endian + varint helpers

extension Data {
    mutating func appendUInt32LE(_ n: UInt32) {
        append(UInt8(truncatingIfNeeded: n))
        append(UInt8(truncatingIfNeeded: n >> 8))
        append(UInt8(truncatingIfNeeded: n >> 16))
        append(UInt8(truncatingIfNeeded: n >> 24))
    }

    mutating func appendUInt64LE(_ n: UInt64) {
        for shift in stride(from: 0, through: 56, by: 8) {
            append(UInt8(truncatingIfNeeded: n >> shift))
        }
    }

    /// Bitcoin variable-length integer:
    ///   < 0xfd            : 1 byte
    ///   ≤ 0xffff          : 0xfd + 2 bytes LE
    ///   ≤ 0xffff_ffff     : 0xfe + 4 bytes LE
    ///   larger            : 0xff + 8 bytes LE
    mutating func appendVarInt(_ n: UInt64) {
        switch n {
        case 0..<0xFD:
            append(UInt8(n))
        case 0xFD...0xFFFF:
            append(0xFD)
            append(UInt8(truncatingIfNeeded: n))
            append(UInt8(truncatingIfNeeded: n >> 8))
        case 0x10000...0xFFFFFFFF:
            append(0xFE)
            appendUInt32LE(UInt32(n))
        default:
            append(0xFF)
            appendUInt64LE(n)
        }
    }
}
