// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AMOUNT_H
#define BITCOIN_AMOUNT_H

#include "serialize.h"

#include <stdlib.h>
#include <string>

typedef int64_t CAmount;

static const CAmount COIN = 100000000;
static const CAmount CENT = 1000000;

/** No amount larger than this (in satoshi) is valid */
static const CAmount MAX_MONEY = 21000000 * COIN;
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

/** Type-safe wrapper class to for fee rates
 * (how much to pay based on transaction size)
 */
class CFeeRate
{
private:
    CAmount nFeePaid;  // amount of fee...
    size_t  nPerBytes; // ...for this many bytes.
public:
    CFeeRate() : nFeePaid(0), nPerBytes(1) { }
    explicit CFeeRate(const CAmount& _nFeePaid): nFeePaid(_nFeePaid), nPerBytes(1000) { }
    CFeeRate(const CAmount& _nFeePaid, size_t _nPerBytes): nFeePaid(_nFeePaid), nPerBytes(_nPerBytes) { }
    CFeeRate(const CFeeRate& other): nFeePaid(other.nFeePaid), nPerBytes(other.nPerBytes) { }

    CAmount GetFee(size_t size) const; // unit returned is satoshis
    CAmount GetFeePerK() const { return GetFee(1000); } // satoshis-per-1000-bytes

    friend bool operator<(const CFeeRate& a, const CFeeRate& b) { return a.nFeePaid * b.nPerBytes < b.nFeePaid * a.nPerBytes; }
    friend bool operator>(const CFeeRate& a, const CFeeRate& b) { return a.nFeePaid * b.nPerBytes > b.nFeePaid * a.nPerBytes; }
    friend bool operator==(const CFeeRate& a, const CFeeRate& b) { return a.nFeePaid * b.nPerBytes == b.nFeePaid * a.nPerBytes; }
    friend bool operator<=(const CFeeRate& a, const CFeeRate& b) { return a.nFeePaid * b.nPerBytes <= b.nFeePaid * a.nPerBytes; }
    friend bool operator>=(const CFeeRate& a, const CFeeRate& b) { return a.nFeePaid * b.nPerBytes >= b.nFeePaid * a.nPerBytes; }
    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        // For compatability reasons the fee rate is serialized as a 64-bit
        // integer. Note that this may involve some loss of precision and
        // therefore is not round-trip-safe. However as currently used this
        // does not pose a problem.
        int64_t nFeePaidPerK;
        if (!ser_action.ForRead())
            nFeePaidPerK = GetFeePerK();
        READWRITE(nFeePaidPerK);
        if (ser_action.ForRead()) {
            nFeePaid  = nFeePaidPerK;
            nPerBytes = 1000;
        }
    }
};

#endif //  BITCOIN_AMOUNT_H
