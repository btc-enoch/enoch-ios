// Tx — Swift mirror of operator/ledger.Transaction.
//
// One file per conceptual component: the type, its Bitcoin canonical
// serialization, the legacy P2PKH SIGHASH_ALL sighash, and the JSON
// wire shape `POST /v1/submit_tx` accepts. Keeping them together
// makes the domain↔wire boundary obvious in one place — the type
// names line up with TxInput / TxOutput / TxBuilder elsewhere in
// the module.
//
// Wire serialization mirrors operator/ledger/script.go::WireBytes
// byte-for-byte. A one-bit drift here produces signatures that look
// valid but verify to false.

import Foundation

// MARK: - Domain types

public struct Tx: Equatable {
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

    /// Witness stack for this input — empty for legacy spends
    /// (P2PKH), non-empty for segwit (P2WPKH, P2TR keypath = single
    /// 64-byte Schnorr sig). Each element is one push onto the
    /// witness stack; serialized to the wire as `varint(elem_count)
    /// + foreach elem: varint(len) + bytes` per BIP-141.
    public var witness: [Data]

    public init(
        txHash: Data,
        vout: UInt32,
        scriptSig: Data = Data(),
        sequence: UInt32 = 0xFFFFFFFF,
        witness: [Data] = []
    ) {
        self.txHash = txHash
        self.vout = vout
        self.scriptSig = scriptSig
        self.sequence = sequence
        self.witness = witness
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

public enum TxError: Swift.Error, Equatable {
    case wrongTxHashLength(input: Int, length: Int)
    case inputIndexOutOfRange(Int)
    case prevoutCountMismatch(have: Int, need: Int)
}

// MARK: - Serialization, hashing, sighash

public extension Tx {
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
    func wireBytes() throws -> Data {
        var out = Data()
        out.appendUInt32LE(version)

        out.appendVarInt(UInt64(inputs.count))
        for (i, input) in inputs.enumerated() {
            guard input.txHash.count == 32 else {
                throw TxError.wrongTxHashLength(input: i, length: input.txHash.count)
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
        // BIP-141: txid = hash of legacy-serialized bytes (no
        // marker/flag/witness, scriptSigs zeroed). For Taproot
        // inputs scriptSig is already empty so witness data is
        // structurally outside the txid commitment — that's
        // exactly what makes Taproot txs non-malleable by witness
        // tweaking.
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
            throw TxError.inputIndexOutOfRange(inputIndex)
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

    /// Per-input prevout context the BIP-341 keypath sighash needs.
    /// Not on TxInput because the wallet learns it from `/v1/utxos`,
    /// not from the tx structure itself.
    struct Prevout: Equatable {
        var amountSatoshi: UInt64
        var scriptPubKey: Data

        init(amountSatoshi: UInt64, scriptPubKey: Data) {
            self.amountSatoshi = amountSatoshi
            self.scriptPubKey = scriptPubKey
        }
    }

    /// BIP-341 keypath sighash for input `inputIndex` under
    /// SIGHASH_DEFAULT (the standard Taproot keypath sighash type).
    ///
    /// Algorithm — `sighash = SHA256_TapSighash(0x00 || preimage)`
    /// where the leading 0x00 is the BIP-341 sighash epoch byte
    /// (always 0x00 today; reserved for future extensions) and
    /// preimage is:
    ///
    ///   hash_type      (1 byte)         0x00 for SIGHASH_DEFAULT
    ///   nVersion       (4 LE)
    ///   nLockTime      (4 LE)
    ///   sha_prevouts   (32)             SHA256 of all input outpoints
    ///   sha_amounts    (32)             SHA256 of all input amounts
    ///   sha_scripts    (32)             SHA256 of all input scriptPubKeys
    ///   sha_sequences  (32)             SHA256 of all input sequences
    ///   sha_outputs    (32)             SHA256 of all output (amount + script)
    ///   spend_type     (1 byte)         0x00 for keypath, no annex
    ///   input_index    (4 LE)
    ///
    /// Total tagged-hash input = 175 bytes (1 epoch + 174 preimage).
    /// Final tagged hash uses tag "TapSighash". `prevouts.count`
    /// MUST equal `inputs.count` — BIP-341 commits to ALL inputs'
    /// amounts + scripts, not just the one being signed.
    ///
    /// Cross-validated byte-for-byte against btcsuite's
    /// `txscript.CalcTaprootSignatureHash`, which is what the operator
    /// uses to verify witness sigs (see TxBIP341SighashTests parity
    /// vector).
    func sighashBIP341Keypath(
        inputIndex: Int,
        prevouts: [Prevout]
    ) throws -> Data {
        guard inputs.indices.contains(inputIndex) else {
            throw TxError.inputIndexOutOfRange(inputIndex)
        }
        guard prevouts.count == inputs.count else {
            throw TxError.prevoutCountMismatch(have: prevouts.count, need: inputs.count)
        }

        var preimage = Data()
        preimage.append(0x00)                           // sighash epoch (BIP-341)
        preimage.append(0x00)                           // hash_type = SIGHASH_DEFAULT
        preimage.appendUInt32LE(version)
        preimage.appendUInt32LE(lockTime)

        // sha_prevouts: SHA256( for each input: txHash(wire) || vout LE )
        var prevoutsBlob = Data()
        for inp in inputs {
            // txHash is in display order on TxInput; wire order is reversed.
            prevoutsBlob.append(Data(inp.txHash.reversed()))
            prevoutsBlob.appendUInt32LE(inp.vout)
        }
        preimage.append(Hashing.sha256(prevoutsBlob))

        // sha_amounts
        var amountsBlob = Data()
        for prev in prevouts {
            amountsBlob.appendUInt64LE(prev.amountSatoshi)
        }
        preimage.append(Hashing.sha256(amountsBlob))

        // sha_scripts: SHA256( for each input: varint(script.count) || script )
        var scriptsBlob = Data()
        for prev in prevouts {
            scriptsBlob.appendVarInt(UInt64(prev.scriptPubKey.count))
            scriptsBlob.append(prev.scriptPubKey)
        }
        preimage.append(Hashing.sha256(scriptsBlob))

        // sha_sequences
        var seqBlob = Data()
        for inp in inputs {
            seqBlob.appendUInt32LE(inp.sequence)
        }
        preimage.append(Hashing.sha256(seqBlob))

        // sha_outputs: SHA256( for each output: amount LE || varint(spk.count) || spk )
        var outputsBlob = Data()
        for out in outputs {
            outputsBlob.appendUInt64LE(out.amount)
            outputsBlob.appendVarInt(UInt64(out.scriptPubKey.count))
            outputsBlob.append(out.scriptPubKey)
        }
        preimage.append(Hashing.sha256(outputsBlob))

        preimage.append(0x00)                           // spend_type = keypath, no annex
        preimage.appendUInt32LE(UInt32(inputIndex))

        return Secp256k1.taggedHash(tag: "TapSighash", data: preimage)
    }
}

// MARK: - JSON wire shape (POST /v1/submit_tx)

/// JSON body for `POST /v1/submit_tx`. Fields mirror the operator's
/// submitTxRequestJSON; binary fields are lowercase hex strings;
/// `tx_hash` is in display order.
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
    /// Optional witness stack as hex strings. Omitted for legacy
    /// (P2PKH) inputs; present (and non-empty) for segwit/Taproot
    /// inputs. The operator's submit_tx handler reads it back into
    /// `ledger.TxInput.Witness [][]byte` and feeds it to the
    /// txscript engine for verification.
    public var witness: [String]?

    public init(txHash: String, vout: UInt32, scriptSig: String, sequence: UInt32, witness: [String]? = nil) {
        self.txHash = txHash
        self.vout = vout
        self.scriptSig = scriptSig
        self.sequence = sequence
        self.witness = witness
    }

    enum CodingKeys: String, CodingKey {
        case txHash = "tx_hash"
        case vout
        case scriptSig = "script_sig"
        case sequence
        case witness
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

// MARK: - Domain ↔ wire bridges

public extension Tx {
    /// Convert to the JSON wire shape POST /v1/submit_tx accepts.
    /// `witness` is omitted from the JSON when empty (legacy P2PKH
    /// inputs), included as an array of hex strings otherwise.
    func toWire() -> SubmitTxRequest {
        SubmitTxRequest(
            version: version,
            inputs: inputs.map { inp in
                TxInputWire(
                    txHash: inp.txHash.hexString,
                    vout: inp.vout,
                    scriptSig: inp.scriptSig.hexString,
                    sequence: inp.sequence,
                    witness: inp.witness.isEmpty ? nil : inp.witness.map { $0.hexString }
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
    /// stored in operator tx-history). Witness, when present in the
    /// JSON, is decoded element-by-element from hex.
    init(wire req: SubmitTxRequest) throws {
        self.version = req.version
        self.lockTime = req.lockTime
        self.inputs = try req.inputs.map { inp in
            let witnessElements: [Data] = try (inp.witness ?? []).map { try Data(hex: $0) }
            return TxInput(
                txHash: try Data(hex: inp.txHash),
                vout: inp.vout,
                scriptSig: try Data(hex: inp.scriptSig),
                sequence: inp.sequence,
                witness: witnessElements
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
