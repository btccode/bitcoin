// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utilmoneystr.h"

#include "primitives/transaction.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

using namespace std;

/* EncodeDouble() transforms a 64-bit IEEE floating-point value into an
 * equal-width integer by means of a 1:1 function which preserves sort
 * ordering, at least for non-NaN values. For two floating point values
 * a and b, if a < b, then EncodeDouble(a) < EncodeDouble(b). This is
 * useful for circumstances such as the coin-control dialog where it
 * makes sense to maintain an hidden integer-valued sort field for the
 * GUI display (see qt/coincontroldialog.cpp).
 *
 * For positive values the floating point format is already defined to
 * be sortable based on encoded representation. Since the result is
 * unsigned, the sign bit is flipped so that negative values sort
 * before positive values. The non-sign bits of negative values also
 * need to be flipped in order to ensure proper ordering of that
 * sequence.
 */
uint64_t EncodeDouble(double d)
{
    const uint64_t wide0 = 0;
    const uint64_t wide1 = 1;
    uint64_t ieee = *(uint64_t*)&d;
    return (((wide1<<63) & ieee)? wide0: ((~wide0) >> 1)) ^ ~ieee;
}

double DecodeDouble(uint64_t lex)
{
    const uint64_t wide0 = 0;
    const uint64_t wide1 = 1;
    uint64_t ieee = (((wide1<<63) & lex)? ((~wide0) >> 1): wide0) ^ ~lex;
    return *(double*)&ieee;
}

string FormatMoney(const CAmount& nIn, bool fPlus)
{
    // Note: not using straight sprintf here because we do NOT want
    // localized number formatting.
    int64_t n = nIn.ToInt64();
    int64_t n_abs = (n > 0 ? n : -n);
    int64_t quotient = n_abs/COIN;
    int64_t remainder = n_abs%COIN;
    string str = strprintf("%d.%08d", quotient, remainder);

    // Right-trim excess zeros before the decimal point:
    int nTrim = 0;
    for (int i = str.size()-1; (str[i] == '0' && isdigit(str[i-2])); --i)
        ++nTrim;
    if (nTrim)
        str.erase(str.size()-nTrim, nTrim);

    if (n < 0)
        str.insert((unsigned int)0, 1, '-');
    else if (fPlus && n > 0)
        str.insert((unsigned int)0, 1, '+');
    return str;
}


bool ParseMoney(const string& str, CAmount& nRet)
{
    return ParseMoney(str.c_str(), nRet);
}

bool ParseMoney(const char* pszIn, CAmount& nRet)
{
    string strWhole;
    int64_t nUnits = 0;
    const char* p = pszIn;
    while (isspace(*p))
        p++;
    for (; *p; p++)
    {
        if (*p == '.')
        {
            p++;
            int64_t nMult = CENT*10;
            while (isdigit(*p) && (nMult > 0))
            {
                nUnits += nMult * (*p++ - '0');
                nMult /= 10;
            }
            break;
        }
        if (isspace(*p))
            break;
        if (!isdigit(*p))
            return false;
        strWhole.insert(strWhole.end(), *p);
    }
    for (; *p; p++)
        if (!isspace(*p))
            return false;
    if (strWhole.size() > 10) // guard against 63 bit overflow
        return false;
    if (nUnits < 0 || nUnits > COIN)
        return false;
    int64_t nWhole = atoi64(strWhole);
    CAmount nValue = nWhole*COIN + nUnits;

    nRet = nValue;
    return true;
}

std::ostream& operator<<(std::ostream &o, const CAmount& n)
{
    o << FormatMoney(n, false);
    return o;
}
