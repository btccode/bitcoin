// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"

#include "tinyformat.h"

CAmount CFeeRate::GetFee(size_t nSize) const
{
    // calculate numerator
    int64_t nFee = nFeePaid * nSize;

    // divide with integer arithmetic, rounding up
    nFee = (nFee + (nPerBytes - 1)) / nPerBytes;

    return nFee;
}

std::string CFeeRate::ToString() const
{
    int64_t nSatoshisPerK = GetFeePerK();
    return strprintf("%d.%08d BTC/kB", nSatoshisPerK / COIN, nSatoshisPerK % COIN);
}
