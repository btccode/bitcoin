// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"

#include "utilmoneystr.h"

CAmount CFeeRate::GetFee(size_t nSize) const
{
    // calculate numerator
    int64_t nFee = (nFeePaid * nSize).ToInt64(ROUND_AWAY_FROM_ZERO);

    // divide with integer arithmetic, rounding up
    nFee = (nFee + (nPerBytes - 1)) / nPerBytes;

    return nFee;
}

std::string CFeeRate::ToString() const
{
    return FormatMoney(GetFeePerK()) + " BTC/kB";
}
