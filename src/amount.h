// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AMOUNT_H
#define BITCOIN_AMOUNT_H

#include "serialize.h"

#include <algorithm> // for swap
#include <stdint.h>
#include <stdlib.h>
#include <stdexcept>
#include <string>

enum RoundingMode
{
    ROUND_TIES_TO_EVEN,
    ROUND_TOWARDS_ZERO,
    ROUND_AWAY_FROM_ZERO,
    ROUND_TOWARD_POSITIVE,
    ROUND_TOWARD_NEGATIVE,
    ROUND_SIGNAL,
};

class amount_error : public std::runtime_error
{
public:
    explicit amount_error(const std::string& str)
        : std::runtime_error(str) {}
};

class invalid_amount_format : public amount_error
{
public:
    explicit invalid_amount_format(const std::string& str)
        : amount_error(str) {}
};

class amount_overflow : public amount_error
                      , public std::overflow_error
{
public:
    explicit amount_overflow(const std::string& str)
        : amount_error(str)
        , std::overflow_error(str) {}
};

class amount_underflow : public amount_error
                       , public std::underflow_error
{
public:
    explicit amount_underflow(const std::string& str)
        : amount_error(str)
        , std::underflow_error(str) {}
};

class CAmount
{
protected:
    int64_t n;

public:
    CAmount() : n(0) {}
    CAmount(int64_t nIn) : n(nIn) {}
    CAmount(const CAmount& other) : n(other.n) {}

    CAmount& operator=(const CAmount& other)
    {
        n = other.n;
        return *this;
    }

    CAmount& swap(CAmount& other)
    {
        std::swap(n, other.n);
        return *this;
    }

    // In units of 1 satoshi
    double ToDouble(RoundingMode mode=ROUND_TIES_TO_EVEN) const
    {
        return static_cast<double>(n);
    }

    // In units of 1 satoshi
    int64_t ToInt64(RoundingMode mode=ROUND_TIES_TO_EVEN) const
    {
        return n;
    }

    CAmount& operator+=(const CAmount& other)
    {
        n += other.n;
        return *this;
    }

    CAmount& operator-=(const CAmount& other)
    {
        n -= other.n;
        return *this;
    }

    CAmount& operator*=(int64_t other)
    {
        n *= other;
        return *this;
    }

    friend std::ostream& operator<<(std::ostream &o, const CAmount& n);

    friend bool operator! (const CAmount& a);
    friend bool operator< (const CAmount& a, const CAmount& b);
    friend bool operator<=(const CAmount& a, const CAmount& b);
    friend bool operator==(const CAmount& a, const CAmount& b);
    friend bool operator!=(const CAmount& a, const CAmount& b);
    friend bool operator>=(const CAmount& a, const CAmount& b);
    friend bool operator> (const CAmount& a, const CAmount& b);

    friend const CAmount operator-(const CAmount& a);
    friend const CAmount operator+(const CAmount& a, const CAmount& b);
    friend const CAmount operator-(const CAmount& a, const CAmount& b);
    friend const CAmount operator*(int64_t a, const CAmount& b);
    friend const CAmount operator*(const CAmount& a, int64_t b);
    friend const CAmount abs(const CAmount& a);
};

namespace std {
template<> inline CAmount numeric_limits<CAmount>::min() throw()
    { return CAmount(std::numeric_limits<int64_t>::min()); }
template<> inline CAmount numeric_limits<CAmount>::max() throw()
    { return CAmount(std::numeric_limits<int64_t>::max()); }
}

inline bool operator!(const CAmount& a)
{
    return a.n == 0;
}

inline bool operator<(const CAmount& a, const CAmount& b)
{
    return a.n < b.n;
}

inline bool operator<=(const CAmount& a, const CAmount& b)
{
    return a.n <= b.n;
}

inline bool operator==(const CAmount& a, const CAmount& b)
{
    return a.n == b.n;
}

inline bool operator!=(const CAmount& a, const CAmount& b)
{
    return a.n != b.n;
}

inline bool operator>=(const CAmount& a, const CAmount& b)
{
    return a.n >= b.n;
}

inline bool operator>(const CAmount& a, const CAmount& b)
{
    return a.n > b.n;
}

inline const CAmount operator-(const CAmount& a)
{
    return CAmount(-a.n);
}

inline const CAmount operator+(const CAmount& a, const CAmount& b)
{
    return CAmount(a.n + b.n);
}

inline const CAmount operator-(const CAmount& a, const CAmount& b)
{
    return CAmount(a.n - b.n);
}

inline const CAmount operator*(int64_t a, const CAmount& b)
{
    return CAmount(a * b.n);
}

inline const CAmount operator*(const CAmount& a, int64_t b)
{
    return CAmount(a.n * b);
}

inline const CAmount abs(const CAmount& a)
{
    return CAmount(abs(a.n));
}

static const int64_t COIN = 100000000;
static const int64_t CENT =   1000000;

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
            nFeePaidPerK = GetFeePerK().ToInt64(ROUND_TIES_TO_EVEN);
        READWRITE(nFeePaidPerK);
        if (ser_action.ForRead()) {
            nFeePaid  = nFeePaidPerK;
            nPerBytes = 1000;
        }
    }
};

#endif //  BITCOIN_AMOUNT_H
