// Copyright (c) 2009-2015 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/foreach.hpp>

#include "hash_map_test_vectors.h"

template<typename Stats>
void CheckStats(const Stats& stats, const ValidationStats::second_type& vs)
{
    std::string strPrefix;
    boost::to_string(stats.prefix, strPrefix);
    BOOST_CHECK_MESSAGE(strPrefix == vs.get<0>(),
        strprintf("stats.prefix is %s, expected %s", strPrefix, vs.get<0>()));
    BOOST_CHECK_MESSAGE(stats.extra.nBalance == vs.get<1>(),
        strprintf("stats.extra.nBalance is %d, expected %d", stats.extra.nBalance, vs.get<1>()));
    BOOST_CHECK_MESSAGE(stats.length == vs.get<2>(),
        strprintf("stats.length is %d, expected %d", stats.length, vs.get<2>()));
    BOOST_CHECK_MESSAGE(stats.count == vs.get<3>(),
        strprintf("stats.count is %d, expected %d", stats.count, vs.get<3>()));
    BOOST_CHECK_MESSAGE(stats.size == vs.get<4>(),
        strprintf("stats.size is %d, expected %d", stats.size, vs.get<4>()));
}

template<typename HashMap>
void CheckIndex(const TestVector& tv, std::vector<unsigned char>& vch, uint224 hash, int nType, int nVersion)
{
    CDataStream ss(nType, nVersion);
    ss << vch;

    uint64_t len = ReadCompactSize(ss);
    HashMap node; ss >> node;
    BOOST_CHECK_MESSAGE(len == ::GetSerializeSize(node, nType, nVersion),
        strprintf("mis-match between specified (%d) and actual (%d) length of node",
            len, ::GetSerializeSize(node, nType, nVersion)));
    std::string strExpected = std::string(vch.begin(), vch.end());
    std::string strActual   = (CDataStream(nType, nVersion) << node).str();
    BOOST_CHECK_MESSAGE(strExpected == strActual,
        strprintf("non-preserved round-trip serialization: expected %s, actual %s", HexStr(strExpected), HexStr(strActual)));
    BOOST_CHECK_MESSAGE(node.GetHash() == hash,
        strprintf("node.GetHash() is 0x%s, expected 0x%s", node.GetHash().ToString(), hash.ToString()));

    BOOST_FOREACH(const ValidationStats& vs, tv.get<3>())
    {
        if (vs.first.empty())
        {
            typename HashMap::stats_type stats;
            BOOST_CHECK(node.GetStats(stats));
            CheckStats(stats, vs.second);
        }

        typename HashMap::stats_type stats;
        BOOST_CHECK(node.GetStats(boost::dynamic_bitset<unsigned char>(vs.first), stats) ^ !vs.second.get<4>());
        CheckStats(stats, vs.second);
    }
}

BOOST_AUTO_TEST_SUITE(hash_map_tests)

BOOST_AUTO_TEST_CASE(validation_index)
{
    const int nType = SER_NETWORK;
    const int nVersion = 0;

    BOOST_FOREACH(TestVector& tv, vInsertionVectors)
        CheckIndex<CValidationIndex>(tv, tv.get<0>(), tv.get<1>(), nType, nVersion);

    BOOST_FOREACH(TestVector& tv, vPruningVectors)
        CheckIndex<CValidationIndex>(tv, tv.get<0>(), tv.get<1>(), nType, nVersion);
}

BOOST_AUTO_TEST_SUITE_END()
