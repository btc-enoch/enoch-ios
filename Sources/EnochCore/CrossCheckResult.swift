// CrossCheckResult — outcome of a K-of-N fan-out across operators.
//
// The wallet's federation-direct client fans out the same query to K
// operators (default K=3) and aggregates responses. The aggregation
// uses each response type's `Equatable` impl as the equivalence
// relation: responses that compare `==` are "the same answer."
//
// Cases follow spec/ios_active_spv.md §4.9.3:
//
//   - .agreement(T): all responding operators returned the same
//     value. The wallet displays it without warning.
//
//   - .majority(T, dissents:): a strict majority (≥ ⌈K/2⌉ + 1)
//     agreed; the rest disagreed or errored. The wallet displays the
//     majority value + a warning naming the dissenting operator(s).
//
//   - .noMajority(responses:): the response set splits with no
//     winner. The wallet blocks sends, surfaces the federation-
//     inconsistency UX, and (if applicable) auto-publishes A6 per
//     §7.3.
//
//   - .allFailed(errors:): every operator was unreachable or
//     errored. The wallet shows offline UX + retry; no trust
//     decision is made.

import Foundation

/// One operator's response to a cross-check query — either a value
/// or the error that prevented us from getting one.
public typealias OperatorResponse<T> = (operatorID: OperatorID, outcome: Result<T, Swift.Error>)

/// Outcome of a K-of-N cross-check. The wallet pattern-matches on
/// this to decide between "display + warn / block / retry."
public enum CrossCheckResult<T> {
    /// Every responding operator returned an equivalent value. No
    /// dissents. `responders` is the set of operators that
    /// successfully responded (errors are excluded).
    case agreement(value: T, responders: [OperatorID])

    /// A strict majority agreed on `value`. `dissents` enumerates
    /// the operators whose response disagreed (or errored) so the
    /// wallet UX can surface "operator X says Y, others say Z."
    case majority(
        value: T,
        agreers: [OperatorID],
        dissents: [OperatorResponse<T>]
    )

    /// No majority emerged — responses split. `responses` is the
    /// full list so the wallet's reconciliation flow can present
    /// every distinct answer and prompt the user.
    case noMajority(responses: [OperatorResponse<T>])

    /// Every operator failed to respond (network down, every
    /// onion unreachable, etc.). The wallet treats this as
    /// transient and retries; it does NOT block sends, but it
    /// does prevent state queries from succeeding.
    case allFailed(errors: [OperatorResponse<T>])
}

extension CrossCheckResult where T: Equatable {
    /// Tally responses by equivalence, picking a winner if a strict
    /// majority (> K/2) emerges. `K` is the number of operators
    /// queried — not the number that responded. An operator that
    /// errored counts toward K but never wins.
    ///
    /// Behaviour:
    ///   - All K responses agree → .agreement
    ///   - One distinct value held by > K/2 responders → .majority
    ///   - No value held by > K/2 → .noMajority (if at least one
    ///     succeeded) or .allFailed (if zero succeeded)
    public static func tally(
        _ responses: [OperatorResponse<T>],
        K: Int
    ) -> CrossCheckResult<T> {
        precondition(K > 0, "K must be positive")
        precondition(
            responses.count == K,
            "CrossCheckResult.tally expects exactly K responses (one per queried operator)"
        )

        let successes: [(OperatorID, T)] = responses.compactMap { resp in
            switch resp.outcome {
            case .success(let v): return (resp.operatorID, v)
            case .failure: return nil
            }
        }

        if successes.isEmpty {
            return .allFailed(errors: responses)
        }

        // Group by equivalence using `==`. We can't use Dictionary
        // because T might not be Hashable; linear scan is fine for
        // K bounded by manifest size (≤ ~20 operators).
        var groups: [(value: T, members: [OperatorID])] = []
        for (opID, value) in successes {
            if let idx = groups.firstIndex(where: { $0.value == value }) {
                groups[idx].members.append(opID)
            } else {
                groups.append((value: value, members: [opID]))
            }
        }

        // All in one group AND all K operators succeeded → unanimous.
        if groups.count == 1 && successes.count == K {
            return .agreement(
                value: groups[0].value,
                responders: groups[0].members
            )
        }

        // Strict majority threshold: more than K/2.
        let threshold = K / 2 + 1
        let winners = groups.filter { $0.members.count >= threshold }

        if let winner = winners.first {
            // Dissents = all responses NOT in the winner's group.
            let winnerSet = Set(winner.members)
            let dissents = responses.filter { resp in
                switch resp.outcome {
                case .success:
                    return !winnerSet.contains(resp.operatorID)
                case .failure:
                    return true
                }
            }
            return .majority(
                value: winner.value,
                agreers: winner.members,
                dissents: dissents
            )
        }

        return .noMajority(responses: responses)
    }
}
