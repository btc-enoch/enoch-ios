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
    public let agentPayoutAddresses: [String]?
    public let withdrawalChallengeWindow: UInt64
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
        case agentPayoutAddresses = "agent_payout_addresses"
        case withdrawalChallengeWindow = "withdrawal_challenge_window"
        case currentHeight = "current_height"
        case feeSchedule = "fee_schedule"
    }
}

/// Loose decode of the operator's fee schedule — wallet displays
/// the per-tx fee but doesn't depend on every field, so we accept
/// missing keys without failing.
public struct FeeSchedule: Codable, Equatable {
    public let perTxFeeSatoshi: UInt64?

    enum CodingKeys: String, CodingKey {
        case perTxFeeSatoshi = "per_tx_fee_satoshi"
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
