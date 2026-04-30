// RIPEMD160 — pure Swift implementation of the 160-bit hash from
// Dobbertin, Bosselaers, and Preneel (1996), used by Bitcoin (and
// Enoch) inside HASH160 = RIPEMD160(SHA256(x)) to derive pubkey
// hashes. Apple's CryptoKit doesn't ship RIPEMD160 (legacy /
// security-deprecated by Apple), so we hand-roll it here.
//
// Spec: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
//
// Constants and round tables match the reference. Tested against
// the canonical test vectors ("", "a", "abc", "message digest",
// etc.) — see RIPEMD160Tests.swift.

import Foundation

public enum RIPEMD160 {
    public static func hash(_ data: Data) -> Data {
        var state: [UInt32] = [
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
        ]
        let padded = pad(data)
        var block = [UInt32](repeating: 0, count: 16)
        for blockStart in stride(from: 0, to: padded.count, by: 64) {
            for i in 0..<16 {
                let off = blockStart + i * 4
                block[i] = UInt32(padded[off])
                    | (UInt32(padded[off + 1]) << 8)
                    | (UInt32(padded[off + 2]) << 16)
                    | (UInt32(padded[off + 3]) << 24)
            }
            compress(&state, block)
        }
        var out = Data(capacity: 20)
        for h in state {
            out.append(UInt8(truncatingIfNeeded: h))
            out.append(UInt8(truncatingIfNeeded: h >> 8))
            out.append(UInt8(truncatingIfNeeded: h >> 16))
            out.append(UInt8(truncatingIfNeeded: h >> 24))
        }
        return out
    }

    /// Append 0x80, then zero-pad to 56 mod 64, then append the
    /// original length as 8 bytes little-endian-of-bits.
    private static func pad(_ data: Data) -> Data {
        let bitLen = UInt64(data.count) * 8
        var padded = data
        padded.append(0x80)
        while padded.count % 64 != 56 {
            padded.append(0x00)
        }
        for i in 0..<8 {
            padded.append(UInt8(truncatingIfNeeded: bitLen >> (i * 8)))
        }
        return padded
    }

    private static func compress(_ state: inout [UInt32], _ block: [UInt32]) {
        var (al, bl, cl, dl, el) = (state[0], state[1], state[2], state[3], state[4])
        var (ar, br, cr, dr, er) = (state[0], state[1], state[2], state[3], state[4])

        for j in 0..<80 {
            let roundL = j / 16
            let roundR = 4 - roundL

            var t = al &+ f(roundL, bl, cl, dl) &+ block[Int(rL[j])] &+ kL[roundL]
            t = rotateLeft(t, by: Int(sL[j])) &+ el
            al = el
            el = dl
            dl = rotateLeft(cl, by: 10)
            cl = bl
            bl = t

            t = ar &+ f(roundR, br, cr, dr) &+ block[Int(rR[j])] &+ kR[roundL]
            t = rotateLeft(t, by: Int(sR[j])) &+ er
            ar = er
            er = dr
            dr = rotateLeft(cr, by: 10)
            cr = br
            br = t
        }

        let t = state[1] &+ cl &+ dr
        state[1] = state[2] &+ dl &+ er
        state[2] = state[3] &+ el &+ ar
        state[3] = state[4] &+ al &+ br
        state[4] = state[0] &+ bl &+ cr
        state[0] = t
    }

    /// Round-dependent nonlinear function. Five distinct shapes,
    /// numbered 0..4 — round indices on the left pipeline run
    /// 0,1,2,3,4 while the right pipeline runs them in reverse.
    private static func f(_ round: Int, _ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        switch round {
        case 0: return x ^ y ^ z
        case 1: return (x & y) | (~x & z)
        case 2: return (x | ~y) ^ z
        case 3: return (x & z) | (y & ~z)
        case 4: return x ^ (y | ~z)
        default: fatalError("RIPEMD160 round \(round) out of range 0..4")
        }
    }

    @inline(__always)
    private static func rotateLeft(_ x: UInt32, by n: Int) -> UInt32 {
        return (x << n) | (x >> (32 - n))
    }

    // MARK: - Constants (per the RIPEMD160 spec)

    private static let kL: [UInt32] = [
        0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E,
    ]
    private static let kR: [UInt32] = [
        0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000,
    ]

    /// Per-step message-word permutation, left pipeline.
    private static let rL: [UInt8] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ]

    /// Per-step message-word permutation, right pipeline.
    private static let rR: [UInt8] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ]

    /// Per-step rotation amounts, left pipeline.
    private static let sL: [UInt8] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ]

    /// Per-step rotation amounts, right pipeline.
    private static let sR: [UInt8] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ]
}
