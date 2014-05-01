// Copyright (c) 2009-2015 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_HASH_MAP_TEST_VECTORS_H
#define BITCOIN_TEST_HASH_MAP_TEST_VECTORS_H

#include "hash_map.h"
#include "primitives/transaction.h"
#include "compressor.h"
#include "util.h"

#include <map>
#include <vector>

#include <boost/tuple/tuple.hpp>

// A version of COutPoint which serializes the index as a big-endian CompactSize,
// in order to preserve lexicographical ordering of key space.
class CValidationOutPoint : public COutPoint
{
public:
    CValidationOutPoint()
        : COutPoint() {}

    CValidationOutPoint(const COutPoint& outpointIn)
        : COutPoint(outpointIn) {}

    CValidationOutPoint(uint256 hashIn, int nIn)
        : COutPoint(hashIn, nIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(hash);
        READWRITE(BIGCOMPACTSIZE(n));
    }
};

// A single unspent transaction output, including the transaction metadata
// needed for validation, serialized in a compact format.
class CValidationCoin : public CTxOut
{
public:
    int nVersion;
    int nHeight;
    bool fCoinBase;

public:
    CValidationCoin()
        : CTxOut()
        , nVersion(0)
        , nHeight(0)
        , fCoinBase(false) {}

    CValidationCoin(const CTxOut& txout, int nVersionIn, int nHeightIn, bool fCoinBaseIn=false)
        : CTxOut(txout)
        , nVersion(nVersionIn)
        , nHeight(nHeightIn)
        , fCoinBase(fCoinBaseIn) {}

    CValidationCoin(const CTransaction& tx, int n, int nHeightIn)
        : CTxOut(tx.vout[n])
        , nVersion(tx.nVersion)
        , nHeight(nHeightIn)
        , fCoinBase(tx.IsCoinBase()) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(VARINT(this->nVersion));
        int nCode;
        if (!ser_action.ForRead())
            nCode = nHeight<<1 | (fCoinBase? 1: 0);
        READWRITE(VARINT(nCode));
        if (ser_action.ForRead()) {
            nHeight   = nCode >> 1;
            fCoinBase = nCode  & 1;
        }
        if (nType == SER_GETHASH)
            READWRITE(static_cast<CTxOut&>(*this));
        else
            READWRITE(REF(CTxOutCompressor(*this)));
    }
};

// To support fraud proofs, each node of the validation index commits to an
// aggregate sum of the bitcoins contained beneath it.
class CValidationExtra
{
public:
    CAmount nBalance;

public:
    CValidationExtra()
        : nBalance(0) {}

    CValidationExtra(const CValidationExtra& other)
        : nBalance(other.nBalance) {}

    CValidationExtra(const CValidationExtra* left, const CValidationExtra* right, const CValidationCoin* data)
        : nBalance(( left?  left->nBalance: 0) +
                   (right? right->nBalance: 0) +
                   (data?   data->nValue:   0)) {}

    CValidationExtra(const CValidationExtra& parent, const CValidationExtra* sibling, bool fBranch)
        : nBalance(parent.nBalance - (sibling? sibling->nBalance: 0)) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (nType == SER_GETHASH)
            READWRITE(VARINT(nBalance));
        else {
            uint64_t nCompressedBalance;
            if (!ser_action.ForRead())
                nCompressedBalance = CTxOutCompressor::CompressAmount(static_cast<CAmount>(nBalance));
            READWRITE(VARINT(nCompressedBalance));
            if (ser_action.ForRead())
                nBalance = static_cast<CAmount>(CTxOutCompressor::DecompressAmount(nCompressedBalance));
        }
    }
};

typedef CHashMap<CValidationOutPoint, CValidationCoin, CValidationExtra> CValidationIndex;

typedef std::pair<CValidationOutPoint, CValidationCoin> ValidationItem;
typedef std::pair<
    const std::string,
    boost::tuple<
        std::string, // prefix (string of 1's and 0's)
        CAmount,     // extra.nBalance
        uint64_t,    // length
        uint64_t,    // count
        uint64_t>    // size
> ValidationStats;

typedef boost::tuple<
    std::vector<unsigned char>, // Prefix tree serialization
    uint224,                    // Prefix tree root hash
    std::map< // elements
        ValidationItem::first_type,
        ValidationItem::second_type>,
    std::map< // sample stats
        ValidationStats::first_type,
        ValidationStats::second_type>
> TestVector;

extern std::vector<TestVector> vInsertionVectors;
extern std::vector<TestVector> vPruningVectors;

#endif // BITCOIN_TEST_HASH_MAP_TEST_VECTORS_H
