// EdgeAPI — typed wire shapes for enoch-edge /v1/* responses.
//
// These mirror the JSON the edge emits (which in turn mirrors what
// the operator emits, with edge-side wrappers on /v1/info). Field
// names use snake_case via CodingKeys so the wire stays canonical
// while Swift call sites get camelCase ergonomics.
//
// Hex-encoded byte fields are kept as `String` here. Conversion to
// `Data` happens at the EdgeClient boundary so accidental string
// vs. data confusion at the call site can't happen.

import Foundation

// MARK: - /v1/info

public struct InfoResponse: Codable, Equatable {
    public let edge: EdgeMetadata
    public let `operator`: OperatorInfo
}

public struct EdgeMetadata: Codable, Equatable {
    public let version: String
    public let protocolVersion: UInt32

    enum CodingKeys: String, CodingKey {
        case version
        case protocolVersion = "protocol_version"
    }
}

/// Mirrors the operator's /info verbatim. Most fields are addresses
/// (enoch1 strings) plus the operator's pubkey + fee schedule.
public struct OperatorInfo: Codable, Equatable {
    public let version: String
    public let protocolVersion: UInt32
    public let network: String
    public let operatorPubkey: String
    public let operatorPayoutAddress: String
    public let feePoolAddress: String
    public let watchtowerPoolAddress: String
    public let reserveAddress: String
    public let bridgeDepositAddress: String
    /// Hex-encoded redeem script from the legacy (pre-FROST) bridge.
    /// Empty under the post-FROST keypath shape; the wallet now
    /// derives per-user deposit addresses via `frostInternalXOnly`.
    /// Kept around so wire format stays backwards-decodable.
    public let bridgeRedeemScript: String?
    /// 32-byte BIP-340 x-only verifying key of the federation's
    /// FROST PKP, hex-encoded. The wallet pairs this with its own
    /// x-only L2 key to derive its per-user keypath-shape deposit
    /// address (FROST stage 7 slice 7b). Optional in the wire shape
    /// so pre-FROST operators decode cleanly; wallets that need to
    /// derive a deposit address fail loudly when it's missing rather
    /// than silently using the wrong (legacy) shape.
    public let frostInternalXOnly: String?
    public let agentPayoutAddresses: [String]?
    public let withdrawalChallengeWindowL1Blocks: UInt64
    /// L1 confirmation threshold the operator gates mints on. Optional
    /// so older operators (pre-this-field) still decode; wallet falls
    /// back to a network-name guess when nil.
    public let minDepositConfirmations: UInt64?
    /// Per-user deposit reclaim relative-timelock, in BIP-68 block-
    /// count units (spec/deposit_address.md). Pinned at federation
    /// init; the wallet must use the same R the operator used or it
    /// will derive an address operators don't credit. Optional in the
    /// wire shape only because pre-Phase-1 operators didn't emit it;
    /// wallets that must derive a deposit address fail loudly when
    /// it's missing rather than silently using a wrong R.
    public let depositReclaimR: UInt32?
    public let currentHeight: UInt64
    public let feeSchedule: FeeSchedule?

    enum CodingKeys: String, CodingKey {
        case version
        case protocolVersion = "protocol_version"
        case network
        case operatorPubkey = "operator_pubkey"
        case operatorPayoutAddress = "operator_payout_address"
        case feePoolAddress = "fee_pool_address"
        case watchtowerPoolAddress = "watchtower_pool_address"
        case reserveAddress = "reserve_address"
        case bridgeDepositAddress = "bridge_deposit_address"
        case bridgeRedeemScript = "bridge_redeem_script"
        case frostInternalXOnly = "frost_internal_xonly"
        case agentPayoutAddresses = "agent_payout_addresses"
        case withdrawalChallengeWindowL1Blocks = "withdrawal_challenge_window_l1_blocks"
        case minDepositConfirmations = "min_deposit_confirmations"
        case depositReclaimR = "deposit_reclaim_r"
        case currentHeight = "current_height"
        case feeSchedule = "fee_schedule"
    }
}

/// Loose decode of the operator's fee schedule — wallet displays
/// the per-tx fee but doesn't depend on every field, so we accept
/// missing keys without failing. The wire key is `per_tx_fee`
/// (matching the operator's Go struct); we expose it under a
/// `*Satoshi` Swift name to make the unit explicit at call sites.
public struct FeeSchedule: Codable, Equatable {
    public let perTxFeeSatoshi: UInt64?

    enum CodingKeys: String, CodingKey {
        case perTxFeeSatoshi = "per_tx_fee"
    }
}

// MARK: - /v1/utxos/{addr}

public struct UTXOsResponse: Codable, Equatable {
    public let address: String
    public let utxos: [UTXOWire]
}

public struct UTXOWire: Codable, Equatable {
    public let txHash: String
    public let vout: UInt32
    public let amount: UInt64
    public let scriptPubKey: String
    public let bondInfo: BondInfo?

    enum CodingKeys: String, CodingKey {
        case txHash = "tx_hash"
        case vout
        case amount
        case scriptPubKey = "script_pubkey"
        case bondInfo = "bond_info"
    }
}

/// Set on UTXOs that hold an operator/agent slashing bond. Plain
/// user-money UTXOs have no bondInfo. Wallets typically just refuse
/// to spend bonded UTXOs they don't recognize.
public struct BondInfo: Codable, Equatable {
    public let operatorPubkey: String
    public let timeoutHeight: UInt64
    public let kind: String?

    enum CodingKeys: String, CodingKey {
        case operatorPubkey = "operator_pubkey"
        case timeoutHeight = "timeout_height"
        case kind
    }
}

// MARK: - /v1/balance/{addr}

public struct BalanceResponse: Codable, Equatable {
    public let address: String
    public let balanceSatoshi: UInt64
    public let utxoCount: Int

    enum CodingKeys: String, CodingKey {
        case address
        case balanceSatoshi = "balance_satoshi"
        case utxoCount = "utxo_count"
    }
}

// MARK: - /v1/address_history/{addr}

public struct AddressHistoryResponse: Codable, Equatable {
    public let address: String
    public let entries: [AddressHistoryEntry]
}

public struct AddressHistoryEntry: Codable, Equatable {
    public let txHash: String
    public let height: UInt64
    public let role: HistoryRole
    public let deltaSatoshi: Int64

    enum CodingKeys: String, CodingKey {
        case txHash = "tx_hash"
        case height
        case role
        case deltaSatoshi = "delta_satoshi"
    }
}

/// Operator-side role labels. "self" = both incoming and outgoing
/// (a self-send / change). "mint" tags a bridge peg-in; "burn" tags
/// a tx that contains an `OP_RETURN ENOCH:WD:` peg-out output.
/// Decoded as String first so an unexpected value (e.g. a future
/// role we don't know) becomes `.unknown` rather than a hard decode
/// failure.
public enum HistoryRole: String, Codable, Equatable {
    case incoming
    case outgoing
    case `self`
    case mint
    case burn
    case unknown

    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = HistoryRole(rawValue: raw) ?? .unknown
    }
}

// MARK: - /v1/fee_oracle

public struct FeeOracleResponse: Codable, Equatable {
    public let source: String
    public let asOf: String  // RFC3339; not parsed here — UI surface
    public let ratesSatPerVB: FeeRates

    enum CodingKeys: String, CodingKey {
        case source
        case asOf = "as_of"
        case ratesSatPerVB = "rates_sat_per_vb"
    }
}

public struct FeeRates: Codable, Equatable {
    public let fastest: UInt64
    public let halfHour: UInt64
    public let hour: UInt64
    public let economy: UInt64
    public let minimum: UInt64

    enum CodingKeys: String, CodingKey {
        case fastest
        case halfHour = "half_hour"
        case hour
        case economy
        case minimum
    }
}

// MARK: - /v1/pending_withdrawals

public struct PendingWithdrawalsResponse: Codable, Equatable {
    public let withdrawals: [PendingWithdrawal]
}

/// One entry from /v1/pending_withdrawals. Wallets correlate
/// against their address-history burn rows (matching `burnTxHash`
/// to the row's `txHash`) to render a "still in flight" status
/// for any withdrawal that hasn't been broadcast yet.
///
/// Once the operator broadcasts to L1, the entry leaves the
/// pending list — the broadcast SSE event gives wallets the
/// btc_txid and removes the "pending" indicator from history.
public struct PendingWithdrawal: Codable, Equatable {
    public let burnTxHash: String
    public let amountSatoshi: UInt64
    public let bitcoinAddress: String
    public let burnHeight: UInt64
    public let completed: Bool
    public let round1QuorumL1Height: UInt64?

    enum CodingKeys: String, CodingKey {
        case burnTxHash = "burn_tx_hash"
        case amountSatoshi = "amount_satoshi"
        case bitcoinAddress = "bitcoin_address"
        case burnHeight = "burn_height"
        case completed
        case round1QuorumL1Height = "round1_quorum_l1_height"
    }
}

// MARK: - POST /v1/submit_tx

public struct SubmitTxResponse: Codable, Equatable {
    public let status: String
    public let txHash: String
    public let burns: Int

    enum CodingKeys: String, CodingKey {
        case status
        case txHash = "tx_hash"
        case burns
    }
}
