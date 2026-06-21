// EdgeEvents — SSE event types for the operator's /v1/events stream.
//
// File name is a vestige of when the iOS wallet went through an
// enoch-edge HTTP proxy (deleted 2026-06-21); the event-payload
// types defined here are still consumed by
// FederationDirectClient.eventStream, which fans out N parallel SSE
// connections (one per operator) and de-duplicates by event kind.
//
// The actual SSE framing parser used to live on EdgeClient; it now
// lives on FederationDirectClient (per-operator) in
// FederationDirectEvents.swift.
//
// Wallets that want explicit reconnect signaling can read the
// `EdgeEvent.connected` events emitted on
// each successful connect.

import Foundation

/// What the wallet sees on the stream. Raw is the operator's
/// `data:` payload as JSON bytes — wallets decode by event type
/// without an intermediate proxy in the way.
public struct EdgeEvent: Equatable {
    public enum Kind: String, Equatable {
        case connected            // synthetic, emitted on each successful upstream connect
        case txApplied            // tx_applied
        case stateRootSigned      // state_root_signed
        case withdrawalStatus     // withdrawal_status — peg-out lifecycle event
        case depositPending       // deposit_pending — L1 deposit seen, awaiting mint (#108)
        case depositMinted        // deposit_minted — mint applied, clear pending (#108)
        case unknown
    }
    public let kind: Kind
    public let raw: Data

    public static func parse(eventName: String, data: Data) -> EdgeEvent {
        let kind: Kind
        switch eventName {
        case "tx_applied":         kind = .txApplied
        case "state_root_signed":  kind = .stateRootSigned
        case "withdrawal_status":  kind = .withdrawalStatus
        case "deposit_pending":    kind = .depositPending
        case "deposit_minted":     kind = .depositMinted
        default:                   kind = .unknown
        }
        return EdgeEvent(kind: kind, raw: data)
    }
}

/// Typed payloads. Decode lazily from `EdgeEvent.raw` only when a
/// wallet caller asks for the typed view — events the wallet
/// doesn't care about (e.g. state_root_signed for a wallet not doing
/// light-client verification) cost nothing to drop.

public struct TxAppliedPayload: Codable, Equatable {
    public let txHash: String
    public let height: UInt64
    public let addresses: [String]
    public let burns: Int

    enum CodingKeys: String, CodingKey {
        case txHash = "tx_hash"
        case height
        case addresses
        case burns
    }
}

public struct StateRootSignedPayload: Codable, Equatable {
    public let height: UInt64
    public let stateRoot: String
    public let signature: String

    enum CodingKeys: String, CodingKey {
        case height
        case stateRoot = "state_root"
        case signature
    }
}

/// Lifecycle event for an in-flight peg-out. The operator emits one
/// at the moment a burn is queued and again at L1 broadcast (which
/// is when `btcTxID` becomes available). Wallet correlates by
/// `burnTxHash` ↔ the address-history row's tx_hash.
///
/// `status` is decoded as a String (not an enum) so unknown future
/// values from a newer operator don't crash the wallet — UI just
/// renders an unknown status as "Processing".
public struct WithdrawalStatusPayload: Codable, Equatable {
    public let burnTxHash: String
    public let status: String
    public let bitcoinAddress: String
    public let amountSatoshi: UInt64
    public let btcTxID: String?

    enum CodingKeys: String, CodingKey {
        case burnTxHash = "burn_tx_hash"
        case status
        case bitcoinAddress = "bitcoin_address"
        case amountSatoshi = "amount_satoshi"
        case btcTxID = "btc_txid"
    }
}

/// Per-user L1 deposit lifecycle — see operator's
/// events.DepositPendingData (#108). `confirmations` advances each
/// watcher tick toward the agent's signing threshold (mainnet=6,
/// testnet=3, regtest=1) so wallets can render a "3/6 confs"
/// progress pill without polling.
///
/// `recipient` matches the wallet's L2 enoch1p... address; the
/// edge filter already restricts the stream to events for the
/// wallet's address, but consumers should still match by recipient
/// before rendering UI to be safe.
///
/// `state` is the operator's lifecycle state for the deposit (#158
/// Phase 4): "detected", "confirming", "signature_pending",
/// "sweeping", "swept". Decoded as a String so unknown future values
/// from a newer operator don't crash the wallet — UI maps via
/// `DepositLifecycleStage` and falls back to a generic stage on
/// unknown values. Optional for backward compat with older
/// operators that don't emit it.
public struct DepositPendingPayload: Codable, Equatable {
    public let recipient: String
    public let btcTxID: String
    public let vout: UInt32
    public let amountSatoshi: UInt64
    public let confirmations: Int
    public let bitcoinHeight: UInt64
    public let perUser: Bool
    public let state: String?

    enum CodingKeys: String, CodingKey {
        case recipient
        case btcTxID = "btc_txid"
        case vout
        case amountSatoshi = "amount_satoshi"
        case confirmations
        case bitcoinHeight = "bitcoin_height"
        case perUser = "per_user"
        case state
    }
}

/// Mint applied — the matching `deposit_pending` entry can be
/// cleared by `btcTxID`. `l2TxHash` cross-references the mint
/// into the wallet's address-history view.
public struct DepositMintedPayload: Codable, Equatable {
    public let recipient: String
    public let btcTxID: String
    public let vout: UInt32
    public let amountSatoshi: UInt64
    public let l2TxHash: String

    enum CodingKeys: String, CodingKey {
        case recipient
        case btcTxID = "btc_txid"
        case vout
        case amountSatoshi = "amount_satoshi"
        case l2TxHash = "l2_tx_hash"
    }
}

public extension EdgeEvent {
    /// Returns nil on shape mismatch — wallets typically `if let`
    /// rather than try/catch in event handling.
    func asTxApplied() -> TxAppliedPayload? {
        try? JSONDecoder().decode(TxAppliedPayload.self, from: raw)
    }

    func asStateRootSigned() -> StateRootSignedPayload? {
        try? JSONDecoder().decode(StateRootSignedPayload.self, from: raw)
    }

    func asWithdrawalStatus() -> WithdrawalStatusPayload? {
        try? JSONDecoder().decode(WithdrawalStatusPayload.self, from: raw)
    }

    func asDepositPending() -> DepositPendingPayload? {
        try? JSONDecoder().decode(DepositPendingPayload.self, from: raw)
    }

    func asDepositMinted() -> DepositMintedPayload? {
        try? JSONDecoder().decode(DepositMintedPayload.self, from: raw)
    }
}


