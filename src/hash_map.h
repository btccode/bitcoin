// Copyright (c) 2009-2015 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HASH_MAP_H
#define BITCOIN_HASH_MAP_H

#include "hash.h"
#include "serialize.h"
#include "streams.h"
#include "tinyformat.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <iterator>
#include <memory>
#include <stdint.h>
#include <vector>

#include <boost/assert.hpp>
#include <boost/dynamic_bitset.hpp>

// Compact prefix: a particularly small encoding of a dynamic bitset for the
// purpose of encoding skip-prefix strings in the links of a compact (Patricia)
// prefix-tree. Behaves similarly to the CVarInt and CFlatData helper classes
// of "serialize.h". See CHashMap for example usage.
template <typename Allocator = std::allocator<void> >
class CPrefixCompressor
{
protected:
    typedef typename Allocator::template rebind<unsigned char>::other _unsigned_char_allocator;
public:
    typedef boost::dynamic_bitset<unsigned char, _unsigned_char_allocator> prefix_type;

protected:
    prefix_type& prefix;

public:
    CPrefixCompressor(prefix_type& prefixIn): prefix(prefixIn) {}

    // The "Code" is a 2-bit integer value used in the flags bitfield of the
    // CHashMap node serialization, which indicates the serialize prefix format.
    // Possible values are:
    //   0: Empty (no branch)
    //   1: Single bit (the implicit bit, 0 for left branch, 1 for right branch)
    //   2: Implicit bit plus 1-7 explicit bits, encoded in a single byte
    //   3: Implicit bit plus 8+ explicit bits, with eight bits per byte
    // Note that in the hash serialization format only two codes are used, (0)
    // and (3), with (3) renumbered (1) so as to leave a reserved bit.
    unsigned char GetCode(int nType, int nVersion) const
    {
        const typename prefix_type::size_type len = prefix.size();
        if (len == 0)                         return 0;
        if (len == 1 || nType == SER_GETHASH) return 1;
        if (len <= 8)                         return 2;
                                              return 3;
    }

    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        const typename prefix_type::size_type len = prefix.size();
        BOOST_ASSERT_MSG(len > 0, "zero-length prefix is not encodable");
        unsigned int size = 0;
        // Hash serialization uses the run-length encoded bitfield
        // serialization format only, so the minimum size of the prefix
        // bitfield is 1.
        if (nType == SER_GETHASH)
            size += ::GetSerializeSize(VARINT(len-1), nType, nVersion);
        // In other serialization formats the run-length encoding encoded
        // bitfield serialization is only used when the prefix bitfield is
        // 9 or more bits long, so we bias the encoded length appropriately.
        else if (9 <= len)
            size += ::GetSerializeSize(VARINT(len-9), nType, nVersion);
        // Note that the implicit bit is not serialized, so a bitfield of
        // length 1 requires zero bytes to encode:
        size += (len + 6) / 8;
        return size;
    }

    template<typename Stream>
    bool Serialize(Stream &s, int nType, int nVersion) const
    {
        const typename prefix_type::size_type len = prefix.size();
        BOOST_ASSERT_MSG(len > 0, "zero-length prefix is not encodable");
        // Hash serialization uses the run-length encoded bitfield format only.
        if (nType == SER_GETHASH)
            s << VARINT(len - 1);
        // Bitfields between 2 and 8 bits in length can be represented in a
        // single byte by using the most significant set bit to communicate
        // the length.
        else if (2 <= len && len <= 8)
          { s << static_cast<unsigned char>(
                (prefix.to_ulong() >> 1) | // Drop the implicit bit.
                (1 << (prefix.size()-1))); // Set the least significant
            return prefix[0]; }            //   unused bit bit. Return.
        // Use the run-length encoding format for longer bitfields, with a
        // bias of 9 applied the prefixed length (since 9 bits -- 1 impicit
        // and 8 explicit bits) is the minimal bitfield length to use this
        // encoding format.
        else if (9 <= len)
            s << VARINT(len - 9);
        // The prefix bitfield is encoded copying bits into a buffer, starting
        // from the least significant bit and movig to the most significant
        // within a byte, and filling bytes in successive order. The extra,
        // unused most significant bits of the final byte (if any) left in
        // their initial zeroed state.
        std::vector<unsigned char> vch((len + 6) / 8, 0);
        for (std::vector<unsigned char>::size_type i = 1; i < prefix.size(); ++i)
            vch[(i-1) / 8] |= prefix[i] << ((i-1) % 8);
        s << CFlatData((char*)&vch.begin()[0], (char*)&vch.end()[0]);
        // Return the first bit of the bitfield, which is not included in the
        // serialization formats.
        return prefix[0];
    }

    template<typename Stream>
    void Unserialize(Stream &s, int nType, int nVersion, unsigned char nCode, bool fImplicit)
    {
        unsigned char ch;
        switch (nCode) {
        case 0:
            // The bitfield is empty.
            prefix.clear();
            return;

        case 1:
            // The bitfield consists only of the implicit bit, which is not
            // part of the serialization. The serialization itself is empty.
            prefix.resize(1);
            break;

        case 2:
            // The serialization consists of a single byte, the most
            // significant set bit encoding the bitfield length. The following
            // code initializes a bitfield of length 9 (the maximum size of 1
            // implicit bit, 7 explicit bits, and the final terminating bit).
            // It then truncates at the position of that most significant set
            // bit.
            s >> ch;
            prefix.resize(1);
            prefix.append(ch);
            if      (ch & 0x80) prefix.resize(8);
            else if (ch & 0x40) prefix.resize(7);
            else if (ch & 0x20) prefix.resize(6);
            else if (ch & 0x10) prefix.resize(5);
            else if (ch & 0x08) prefix.resize(4);
            else if (ch & 0x04) prefix.resize(3);
            else                prefix.resize(2);
            break;

        case 3:
            // The length is serialized as a variable-length integer with a
            // bias of 9, the minimal size of a code-3 serialized prefix,
            // including the implicit leading bit.
            typename prefix_type::size_type len = 0;
            s >> VARINT(len);
            len += 9;
            // Allocate space for the implicit bit, and then append the
            // necessary number of bytes from the stream.
            typename prefix_type::size_type bytes = (len + 7) / 8;
            prefix.resize(1);
            while (bytes--)
            {
                s >> ch;
                prefix.append(ch);
            }
            // Truncate any extra high-order bits in the final byte.
            prefix.resize(len);
            break;
        }
        // Set the implicit bit.
        prefix[0] = fImplicit;
    }
};

// A helper class which serves as the default template parameter for hash tree
// key serialization. It is capible of serializing objects of type Key into a
// boost::dynamic_bitset<unsigned char> which is used as the insert key into
// the hash tree.
//
// By default this is performed by serializing the object and converting the
// serialized representation into a bitset using big-endian ordering within
// octets (higher order bits come first so as to preserve lexegraphical sort
// ordering). There is a specialization which alters this behavior: serializing
// prefix objects directly, which is considered a NOP (see below).
template<
    typename Key,
    typename Allocator = std::allocator<void> >
class CPrefixSerializer
{
private:
    typedef typename Allocator::template rebind<unsigned char>::other _unsigned_char_allocator;
public:
    typedef boost::dynamic_bitset<unsigned char, _unsigned_char_allocator> prefix_type;

public:
    // Note that this resembles but is not conformant to the usual serialize.h
    // API for data serialization. These serialize to/from a prefix_type object
    // and the serialization size is measured in bits, not bytes.
    static unsigned int GetSerializeSize(const Key& key, int nType, int nVersion)
    {
        return 8 * ::GetSerializeSize(key, nType, nVersion);
    }

    static void Serialize(prefix_type& prefix, const Key& key, int nType, int nVersion)
    {
        CDataStream ds(nType, nVersion); ds << key;
        prefix.clear();
        for (CDataStream::iterator i = ds.begin(); i != ds.end(); ++i)
            // dynamic_bitset appends the least significant bits first, which
            // is the opposite ordering of what we desire. So first the bits
            // of each byte need to be reversed.
            prefix.append(vReverseBitsOfOctet[static_cast<unsigned char>(*i)]);
    }

    static void Unserialize(Key& key, const prefix_type& prefix, int nType, int nVersion)
    {
        // Boost's to_block_range function will convert a dynamic_bitset back
        // into a sequence of bytes, when used properly.
        std::vector<unsigned char> vch;
        vch.reserve((prefix.size() + 7) / 8);
        boost::to_block_range(prefix, std::back_inserter(vch));
        // We reversed the bits of each byte in order to preserve lexegraphical
        // sort order. We must undo that bit-order reversal now before attemptig
        // to deserialize the key object.
        for (std::vector<unsigned char>::iterator i = vch.begin(); i != vch.end(); ++i)
            *i = vReverseBitsOfOctet[*i];
        // Use the standard serialize.h serialization API for deserializing the
        // key object.
        CDataStream ds(vch, nType, nVersion);
        ds >> key;
    }
};

// As a special case, serializing / deserializing a dynamic_bitset to / from
// a prefix_type is a NOP. This pass-through serializer is not so much a
// performance improvement as a mechanism for having exact control over the
// keys used.
template<typename Allocator>
class CPrefixSerializer<boost::dynamic_bitset<unsigned char, Allocator>, Allocator>
{
private:
    typedef typename Allocator::template rebind<unsigned char>::other _unsigned_char_allocator;
public:
    typedef boost::dynamic_bitset<unsigned char, _unsigned_char_allocator> prefix_type;

public:
    static unsigned int GetSerializeSize(const prefix_type& key, int nType, int nVersion)
        { return key.size(); }
    static void Serialize(prefix_type& prefix, const prefix_type& key, int nType, int nVersion)
        { prefix = key; }
    static void Unserialize(prefix_type& key, const prefix_type& prefix, int nType, int nVersion)
        { key = prefix; }
};

// Forward declarations. Link and Node are mostly internal structures used by
// the CHashMap implementation, but are necessarily exposed as the compressed
// and uncompressed variants are used as specialization parameters to CHashMap.
template<
    typename Container,
    typename Patricia = boost::true_type>
class CHashMapLink;

template<
    typename Container,
    typename deLaBrandais = boost::true_type>
class CHashMapNode;

template<
    typename Key,
    typename Data,
    typename Extra,
    typename Patricia = boost::true_type,
    typename deLaBrandais = boost::true_type,
    template<typename _Key, typename Allocator>
        class Serializer = CPrefixSerializer,
    typename Allocator = std::allocator<void> >
class CHashMap;

// A left- or right-link of a node, connecting an internal node to one of its
// children along with the skip prefix and associated metadata.
template<
    typename Container,
    typename Patricia>
class CHashMapLink
{
public:
    typename Container::prefix_type prefix;
    typename Container::node_type* node;
    uint224 hash;

protected:
    uint224 _link_hash; // post-processed [see _ComputeLinkHash()]
    typename Container::size_type _count; // The number of values in the branch.
    typename Container::size_type _size;  // The canonical serialization size
                                          //   of the branch.

public:
    // Default constructor
    CHashMapLink()
        : prefix()
        , node(0)
        , hash()
        , _link_hash()
        , _count(0)
        , _size(0) {}

    // Copy constructor
    CHashMapLink(const CHashMapLink<Container, Patricia>& other)
        : prefix(other.prefix)
        , node(0)
        , hash(other.hash)
        , _link_hash(other._link_hash)
        , _count(other._count)
        , _size(other._size)
    {
        if (other.node) {
            typename Container::allocator_type& allocator = other.node->get_allocator();
            node = allocator.allocate(1, this);
            allocator.construct(node, other.node);
        }
    }

    // Construct from explicit node (unpruned).
    CHashMapLink(const typename Container::prefix_type& prefixIn, typename Container::node_type& nodeIn)
        : prefix(prefixIn)
        , hash(nodeIn.GetHash())
        , _link_hash()
        , _count(nodeIn.GetCount())
        , _size(nodeIn.GetSerializedSize())
    {
        typename Container::allocator_type& allocator = nodeIn.get_allocator();
        node = allocator.allocate(1, this);
        allocator.construct(node, nodeIn);
    }

    // Construct from node hash and metadata only (pruned).
    CHashMapLink(const typename Container::prefix_type& prefixIn, const uint224 hashIn, typename Container::size_type countIn, typename Container::size_type sizeIn)
        : prefix(prefixIn)
        , node(0)
        , hash(hashIn)
        , _link_hash()
        , _count(countIn)
        , _size(sizeIn) {}

    ~CHashMapLink()
    {
        if (node) {
            typename Container::allocator_type& allocator = node->get_allocator();
            allocator.destroy(node);
            allocator.deallocate(node, 1);
            node = 0;
        }
    }

    // Standard serialize.h API, with some minor modifications. See
    // CHashMapNode and CHashMap serialization routines for context.
    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        unsigned int size = 0;
        size += ::GetSerializeSize(typename Container::prefix_compressor(REF(prefix)), nType, nVersion);
        if (nType != SER_GETHASH)
        {
            if (IsPruned())
                size += ::GetSerializeSize(hash, nType, nVersion);
            else
                size += ::GetSerializeSize(*node, nType, nVersion);
        }
        if ((nType == SER_GETHASH) || IsPruned())
        {
            size += ::GetSerializeSize(VARINT(_count), nType, nVersion);
            size += ::GetSerializeSize(VARINT(_size), nType, nVersion);
        }
        return size;
    }

    // The implicit bit (which is not included in the serialization!) is returned.
    // Since C++ does not differentiate based on return type, this API is still
    // compatible with the serialize.h framework.
    template<typename Stream>
    bool Serialize(Stream &s, int nType, int nVersion) const
    {
        bool fImplicit;
        if (!Patricia::value && (nType == SER_GETHASH))
            // Should never be called with an empty prefix, but just in case...
            fImplicit = prefix.size()? prefix[0]: false;
        else
            fImplicit = typename Container::prefix_compressor(REF(prefix)).Serialize(s, nType, nVersion);
        if (nType != SER_GETHASH) {
            if (IsPruned())
                ::Serialize(s, hash, nType, nVersion);
            else
                ::Serialize(s, *node, nType, nVersion);
        }
        if ((nType == SER_GETHASH) || IsPruned())
        {
            ::Serialize(s, VARINT(_count), nType, nVersion);
            ::Serialize(s, VARINT(_size), nType, nVersion);
        }
        return fImplicit;
    }

    // Deserialization of a link requires extra context: the container being
    // serialized, the enclosing node, the implicit bit (left or right), the
    // prefix code (a 4-value enumeration), and whether or not the link is
    // pruned. So unfortunately, we break from the serialize.h API in an
    // incompatible way.
    //
    // A pair of pointers is returned to the first and last non-pruned
    // elements, to be used by the container in implementing front() and
    // back() in O(1) time.
    template<typename Stream>
    std::pair<typename Container::node_type*, typename Container::node_type*> Unserialize(Stream &s, int nType, int nVersion, Container& containerIn, typename Container::node_type& nodeIn, unsigned char nCode, bool fImplicit, bool fPruned=false)
    {
        if (nType == SER_GETHASH)
            throw std::runtime_error("Unserialization of CHashMapLink in SER_GETHASH mode is not possible because node/hash information is out of band.");

        // The min and max elements will be filled in if any child nodes have
        // values and are unpruned, but for now will fill with the fallback
        // return value: null pointers indicating an no unpruned items.
        std::pair<typename Container::node_type*, typename Container::node_type*> ret =
            std::make_pair(static_cast<typename Container::node_type*>(0),
                           static_cast<typename Container::node_type*>(0));

        // A Container::node_type allocator.
        typename Container::allocator_type& allocator = nodeIn.get_allocator();

        typename Container::prefix_compressor(REF(prefix)).Unserialize(s, nType, nVersion, nCode, fImplicit);
        if (fPruned) {
            if (node) {
                allocator.destroy(node);
                allocator.deallocate(node, 1);
                node = 0;
            }
            ::Unserialize(s, hash, nType, nVersion);
            ::Unserialize(s, VARINT(_count), nType, nVersion);
            ::Unserialize(s, VARINT(_size), nType, nVersion);
        } else {
            if (node)
                allocator.destroy(node);
            else
                node = allocator.allocate(1, this);
            new(node) typename Container::node_type();
            ret = node->Unserialize(s, nType, nVersion, containerIn, &nodeIn, fImplicit);
            hash = node->GetHash();
            _count = node->GetCount();
            _size = node->GetSize();
        }
        return ret;
    }

protected:
    // Computes the hash value for a link, which is the hash value used by the
    // enclosing node. When Patricia compression is not used, this requires
    // computing the hash of an intermediate node for each bit in the skiplist.
    void _ComputeLinkHash(uint224& link_hash) const
    {
        if (!Patricia::value) {
            const uint224  LEFT_INFO_HASH = (CHashWriter224(SER_GETHASH, 0)
                << '\x01' << '\x00' << VARINT(_count) << VARINT(_size)).GetHash();
            const uint224 RIGHT_INFO_HASH = (CHashWriter224(SER_GETHASH, 0)
                << '\x04' << '\x00' << VARINT(_count) << VARINT(_size)).GetHash();
            for (typename Container::prefix_type::size_type i = prefix.size() - 1; i > 0; --i)
                link_hash = (CHashWriter224(SER_GETHASH, 0) << (prefix[i]? RIGHT_INFO_HASH: LEFT_INFO_HASH)
                                                            << link_hash).GetHash();
        }
    }

public:
    // Whether or not Patricia compression is used, as specified by the
    // Patricia template parameter.
    typedef Patricia patricia_type;
    static const bool fPatricia = Patricia::value;

    // Pruned links have their branches deallocated. Only the hash value and
    // metadata are kept, allowing the root hash to still be validated.
    bool IsPruned() const
        { return node==0; }

    // The extra field contains additional aggregate data about a branch. If
    // a branch is pruned it is still recoverable so long as the sibling link
    // is not also pruned. This method returns the extra data about a branch,
    // using that recovery logic when necessary. The return value indicates
    // whether the extra field was successfully found/recovered.
    bool GetExtra(const typename Container::node_type& parent, bool fBranch, typename Container::extra_type& extra)
    {
        if (!IsPruned())
            extra = node->extra;
        else {
            if (fBranch) {
                if (parent.left && parent.left->IsPruned()) {
                    // If both branches are pruned, then it is impossible to
                    // separate the contribution of this branch from its sibling.
                    extra = typename Container::extra_type(0, 0, 0);
                    return false;
                }
                // Use the sibling constructor for the extra_type.
                extra = typename Container::extra_type(
                    parent.extra, parent.left? &parent.left->node->extra: 0, fBranch);
            } else {
                if (parent.right && parent.right->IsPruned())
                    { extra = typename Container::extra_type(0, 0, 0); return false; }
                // Use the sibling constructor for the extra_type.
                extra = typename Container::extra_type(
                    parent.extra, parent.right? &parent.right->node->extra: 0, fBranch);
            }
        }
        return true;
    }

    // The number of unpruned items within the linked sub-tree.
    typename Container::size_type GetLength() const
        { return IsPruned()? 0: node->GetLength(); }

    // The number of pruned and unpruned items within the linked sub-tree.
    typename Container::size_type GetCount() const
        { return _count; }

    // The number of bytes used in the canonical serialized representation of
    // the sub-tree.
    typename Container::size_type GetSize() const
        { return _size; }

    // The actual hash of the linked node.
    uint224 GetNodeHash()
    {
        if (hash.IsNull() && node)
            hash = node->GetHash();
        return hash;
    }

    uint224 GetNodeHash() const
    {
        if (hash.IsNull() && node)
            return node->GetHash();
        return hash;
    }

    // The post-processed hash ready for use in the enclosing node
    // [see _ComputeLinkHash()]
    uint224 GetLinkHash()
    {
        if (_link_hash.IsNull()) {
            _link_hash = GetNodeHash();
            _ComputeLinkHash(_link_hash);
        }
        return _link_hash;
    }

    uint224 GetLinkHash() const
    {
        if (!_link_hash.IsNull())
            return _link_hash;
        uint224 link_hash = GetNodeHash();
        _ComputeLinkHash(link_hash);
        return link_hash;
    }
};

//template<typename Container, typename Patricia>
//const bool CHashMapLink<Container, Patricia>::fPatricia = Patricia::value;

// An node of the hash tree, with an optional and possibly pruned data value.
// See CHashMap for context.
template<
    typename Container,
    typename deLaBrandais>
class CHashMapNode
{
protected:
    // Pointers to both the container and the parent node are required to
    // support iterator traversal and updates which affect container metadata.
    Container* _container;
    CHashMapNode<Container, deLaBrandais>* _parent;

public:
    // Null pointer indicates the absence of the left or right branch or data
    // value for this node. Prune status of a branch is tracked within the link
    // structure, and data pruning is indicated by the _pruned field.
    typename Container::link_type* left;
    typename Container::link_type* right;
    typename Container::data_type* data; // see _pruned
    typename Container::extra_type extra;

protected:
    // The number of non-pruned items within the sub-tree rooted at this node,
    // inclusive of this node.
    typename Container::size_type _length;
    bool _pruned;
    bool _branch; // false:left, true:right

public:
    // A Container::node_type allocator.
    typedef typename Container::allocator_type allocator_type;
    allocator_type& get_allocator()
        { return _container->get_allocator(); }
    const allocator_type& get_allocator() const
        { return _container->get_allocator(); }

protected:
    // Constants for the flags meta-field.
    static const unsigned char LEFT_MASK    = 0x03;
    static const           int LEFT_OFFSET  = 0;
    static const unsigned char RIGHT_MASK   = 0x0c;
    static const           int RIGHT_OFFSET = 2;
    static const           int HAS_DATA     = 4;
    static const unsigned char HASH_MASK    = 0x1f;
    static const           int PRUNE_LEFT   = 5;
    static const           int PRUNE_RIGHT  = 6;
    static const           int PRUNE_DATA   = 7;

public:
    // Whether or not Patricia compression is used, as specified by the
    // Patricia template parameter.
    typedef deLaBrandais de_la_brandais_type;
    static const bool fDeLaBrandais = deLaBrandais::value;

public:
    CHashMapNode()
        : _container(0)
        , _parent(0)
        , left(0)
        , right(0)
        , data(0)
        , extra(0, 0, 0)
        , _length(0)
        , _pruned(false)
        , _branch(false) {}

    ~CHashMapNode()
    {
        if (left && _container) {
            _container->_get_Link_allocator().destroy(left);
            _container->_get_Link_allocator().deallocate(left, 1);
        }
        left = 0;
        if (right && _container) {
            _container->_get_Link_allocator().destroy(right);
            _container->_get_Link_allocator().deallocate(right, 1);
        }
        right = 0;
        if (data && _container) {
            _container->_get_Data_allocator().destroy(data);
            _container->_get_Data_allocator().deallocate(data, 1);
        }
        data = 0;
        // extra will be destroyed by C++
        _length = 0;
        _pruned = false;
        _branch = false;
        _parent = 0;
        _container = 0;
    }

    unsigned char GetFlags(int nType, int nVersion) const
    {
        unsigned char flags = 0;
        if (left)                       flags |= typename Container::prefix_compressor(left->prefix).GetCode(nType, nVersion)  << LEFT_OFFSET;
        if (right)                      flags |= typename Container::prefix_compressor(right->prefix).GetCode(nType, nVersion) << RIGHT_OFFSET;
        if (data)                       flags |= (1 << HAS_DATA);
        if (left && left->IsPruned())   flags |= (1 << PRUNE_LEFT);
        if (right && right->IsPruned()) flags |= (1 << PRUNE_RIGHT);
        if (data && IsPruned())         flags |= (1 << PRUNE_DATA);
        return flags;
    }

    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        unsigned int len, size = 1; // flags
        if ((nType == SER_GETHASH) || (left && left->IsPruned()) || (right && right->IsPruned()) || (data && _pruned)) {
            len = ::GetSerializeSize(extra, nType, nVersion);
            size += ::GetSerializeSize(VARINT(len), nType, nVersion) + len;
        }
        if (data) {
            len = ::GetSerializeSize(*data, nType, nVersion);
            size += ::GetSerializeSize(VARINT(len), nType, nVersion);
            if (nType != SER_GETHASH)
                size += len;
        }
        if (left)  size += ::GetSerializeSize(*left, nType, nVersion);
        if (right) size += ::GetSerializeSize(*right, nType, nVersion);
        return size;
    }

    template<typename Stream>
    void Serialize(Stream &s, int nType, int nVersion) const
    {
        unsigned char flags = GetFlags(nType, nVersion);
        if (nType == SER_GETHASH) {
            if (!Container::link_type::fPatricia) {
                const unsigned char nLeftCode = (flags & LEFT_MASK) >> LEFT_OFFSET;
                if (nLeftCode)
                    flags = (flags & ~LEFT_MASK) | (1 << LEFT_OFFSET);
                const unsigned char nRightCode = (flags & RIGHT_MASK) >> RIGHT_OFFSET;
                if (nRightCode)
                    flags = (flags & ~RIGHT_MASK) | (1 << RIGHT_OFFSET);
            }
            flags &= HASH_MASK;
        }
        s << flags;
        if ((nType == SER_GETHASH) || (left && left->IsPruned()) || (right && right->IsPruned()) || (data && _pruned)) {
            s << VARINT(::GetSerializeSize(extra, nType, nVersion));
            s << extra;
        }
        if (data) {
            s << VARINT(::GetSerializeSize(*data, nType, nVersion));
            if (nType != SER_GETHASH) {
                if (_pruned)
                    // FIXME: actually prune pruned data...
                    s << SerializeHash224(*data, nType, nVersion);
                else
                    s << *data;
            }
        }
        if (left) {
            bool fImplicit = left->Serialize(s, nType, nVersion);
            BOOST_ASSERT_MSG(fImplicit == false, "serialized a right link on the left branch (fImplicit is true, expected false)");
        }
        if (right) {
            bool fImplicit = right->Serialize(s, nType, nVersion);
            BOOST_ASSERT_MSG(fImplicit == true, "serialized a left link on the right branch (fImplicit is false, expected true)");
        }
    }

    // Deserialization requires a reference to the container and a pointer to
    // the parent node as context, and so necessarily diverges from the
    // serialize.h API. See also CHashMapLink::Unserialize().
    //
    // The return value is a pair of pointers to the first and last non-pruned
    // items in the sub-tree rooted on this node, or null if the branch is empty
    // or fully pruned.
    template<typename Stream>
    std::pair<CHashMapNode<Container, deLaBrandais>*, CHashMapNode<Container, deLaBrandais>*> Unserialize(Stream &s, int nType, int nVersion, Container& containerIn, CHashMapNode<Container, deLaBrandais>* parentIn, bool fBranch)
    {
        if (nType == SER_GETHASH)
            throw std::runtime_error("Unserialization of CHashMapNode in SER_GETHASH mode is not possible because some information has been irrevocably destroyed under a one-way hash.");

        // The default return value when this branch of the hash tree is empty
        // or fully pruned is two null pointers for the first and last element.
        // These will be replaced later when non-pruned sub-elements are
        // encountered.
        std::pair<CHashMapNode<Container, deLaBrandais>*, CHashMapNode<Container, deLaBrandais>*> ret =
            std::make_pair(static_cast<CHashMapNode<Container, deLaBrandais>*>(0),
                           static_cast<CHashMapNode<Container, deLaBrandais>*>(0));

        _container = &containerIn;
        _parent = parentIn;
        _branch = fBranch;

        unsigned char flags;
        ::Unserialize(s, flags, nType, nVersion);

        const unsigned char nLeftCode = (flags & LEFT_MASK) >> LEFT_OFFSET;
        const unsigned char nRightCode = (flags & RIGHT_MASK) >> RIGHT_OFFSET;
        const bool fHasData = flags & (1 << HAS_DATA);
        const bool fPruneLeft = flags & (1 << PRUNE_LEFT);
        const bool fPruneRight = flags & (1 << PRUNE_RIGHT);
        const bool fPruneData = flags & (1 << PRUNE_DATA);

        unsigned int len = 0;
        bool fExplicitExtra = (nLeftCode && fPruneLeft) || (nRightCode && fPruneRight) || (fHasData && fPruneData);
        if (fExplicitExtra) {
            ::Unserialize(s, VARINT(len), nType, nVersion);
            ::Unserialize(s, extra, nType, nVersion);
            BOOST_ASSERT_MSG(len == ::GetSerializeSize(extra, nType, nVersion),
                strprintf("mis-match between specified (%d) and actual (%d) length of extra field: %s",
                          len, ::GetSerializeSize(extra, nType, nVersion),
                          HexStr((CDataStream(nType, nVersion) << extra).str())).c_str());
        }

        if (data)
            _container->_get_Data_allocator().destroy(data);
        if (fHasData) {
            ::Unserialize(s, VARINT(len), nType, nVersion);
            // FIXME: handle pruned data, where there will be a hash instead
            //        of the actual data...
            if (!data)
                data = _container->_get_Data_allocator().allocate(1, this);
            new(data) typename Container::data_type();
            ::Unserialize(s, *data, nType, nVersion);
            BOOST_ASSERT_MSG(len == ::GetSerializeSize(*data, nType, nVersion),
                strprintf("mis-match between specified (%d) and actual (%d) length of data field: %s",
                          len, ::GetSerializeSize(*data, nType, nVersion),
                          HexStr((CDataStream(nType, nVersion) << *data).str())).c_str());
            if (!fPruneData)
                ret = std::make_pair(this, this);
        } else if (data) {
            _container->_get_Data_allocator().deallocate(data, 1);
            data = 0;
        }
        _pruned = fPruneData;

        _length = fHasData && !fPruneData;
        std::pair<CHashMapNode<Container, deLaBrandais>*, CHashMapNode<Container, deLaBrandais>*> minmax;
        #define CHashMapNode_Unserialize_branch(pLink, nCode, fImplicit, fPruned) \
            if (pLink) \
                _container->_get_Link_allocator().destroy(pLink); \
            if (nCode) { \
                if (!pLink) \
                    pLink = _container->_get_Link_allocator().allocate(1, this); \
                new(pLink) typename Container::link_type(); \
                minmax = pLink->Unserialize(s, nType, nVersion, containerIn, *this, nCode, fImplicit, fPruned); \
                _length += pLink->GetLength(); \
            } else if (pLink) { \
                _container->_get_Link_allocator().deallocate(pLink, 1); \
                pLink = 0; \
            }
        CHashMapNode_Unserialize_branch(left, nLeftCode, false, fPruneLeft)
        if (nLeftCode && !fPruneLeft) {
            ret.first = minmax.first;
            if (!ret.second)
                ret.second = minmax.second;
        }
        CHashMapNode_Unserialize_branch(right, nRightCode, true, fPruneRight)
        if (nRightCode && !fPruneRight) {
            if (!ret.first)
                ret.first = minmax.first;
            ret.second = minmax.second;
        }
        #undef CHashMapNode_Unserialize_branch

        if (!fExplicitExtra) {
            _container->_get_Extra_allocator().destroy(&extra);
            new (&extra) typename Container::extra_type(left? &left->node->extra: 0,
                                                        right? &right->node->extra: 0, data);
        }

        return ret;
    }

public:
    bool IsPruned() const
        { return _pruned; }

    // The number of unpruned items within the proof rooted at this node.
    typename Container::size_type GetLength() const
        { return _length; }

    // The number of pruned and unpruned items within the sub-tree rooted
    // at this node.
    typename Container::size_type GetCount() const
    {
        typename Container::size_type count = data? 1: 0;
        if (left)  count += left->GetCount();
        if (right) count += right->GetCount();
        return count;
    }

    // The number of bytes used in the canonical serialized representation
    // of the sub-tree.
    typename Container::size_type GetSize() const
    {
        typename Container::size_type len, size = 1; // flags
        if (data) {
            len = ::GetSerializeSize(*data, SER_GETHASH, 0);
            size += ::GetSerializeSize(VARINT(len), SER_GETHASH, 0) + len;
        }
        if (left)  size += ::GetSerializeSize(typename Container::prefix_compressor(left->prefix), SER_GETHASH, 0) + left->GetSize();
        if (right) size += ::GetSerializeSize(typename Container::prefix_compressor(right->prefix), SER_GETHASH, 0) + right->GetSize();
        return size;
    }

    uint224 GetHash() const
    {
        CDataStream ds(SER_GETHASH, 0);
        ds << *this;

        if (!deLaBrandais::value || data) {
            uint224 info_hash = SerializeHash224(ds);
            // FIXME: actually prune pruned data...
            uint224 data_hash = data? SerializeHash224(*data): uint224();
            ds.clear();
            ds << info_hash << data_hash;
        }

        uint224 left_hash = left? left->GetLinkHash(): uint224();
        uint224 right_hash = right? right->GetLinkHash(): uint224();
        const bool fHasLeftHash = !deLaBrandais::value || !!left;
        const bool fHasRightHash = !deLaBrandais::value || !!right;
        if (fHasLeftHash || fHasRightHash) {
            if (fHasLeftHash) {
                if (fHasRightHash) {
                    CHashWriter224 hs(SER_GETHASH, 0);
                    hs << left_hash << right_hash;
                    right_hash = hs.GetHash();
                } else {
                    right_hash = left_hash;
                }
            }
            left_hash = SerializeHash224(ds);
            ds.clear();
            ds << left_hash << right_hash;
        }

        return SerializeHash224(ds);
    }
};

template<
    typename Key,
    typename Data,
    typename Extra,
    typename Patricia,
    typename deLaBrandais,
    template<typename _Key, typename Allocator>
        class Serializer,
    typename Allocator>
class CHashMap
{
public:
    typedef uint64_t size_type;
    typedef int64_t difference_type;

public:
    typedef typename Allocator::template rebind<Key>::other _Key_allocator;
    typedef typename Allocator::template rebind<Data>::other _Data_allocator;
    typedef typename Allocator::template rebind<std::pair<const Key, Data> >::other _Value_allocator;
    typedef typename Allocator::template rebind<Extra>::other _Extra_allocator;
    typedef typename Allocator::template rebind<CHashMap<Key,Data,Extra,Patricia,deLaBrandais,Serializer,Allocator> >::other _Container_allocator;
    typedef typename Allocator::template rebind<CHashMapLink<typename _Container_allocator::value_type, Patricia> >::other _Link_allocator;
    typedef typename Allocator::template rebind<CHashMapNode<typename _Container_allocator::value_type, deLaBrandais> >::other _Node_allocator;
    typedef typename Allocator::template rebind<unsigned char>::other _unsigned_char_allocator;

    // Actually store the allocator in its node allocator form, as that is how
    // it is most often used (in case the compiler has trouble optimizing away
    // the various rebinding and conversions).
    typedef _Node_allocator allocator_type;

    allocator_type _allocator;

    allocator_type& get_allocator()
        { return _allocator; }
    const allocator_type& get_allocator() const
        { return _allocator; }

    inline _Key_allocator _get_Key_allocator() const
        { return _Key_allocator(_allocator); }
    inline _Data_allocator _get_Data_allocator() const
        { return _Data_allocator(_allocator); }
    inline _Value_allocator _get_Value_allocator() const
        { return _Value_allocator(_allocator); }
    inline _Extra_allocator _get_Extra_allocator() const
        { return _Extra_allocator(_allocator); }
    inline _Container_allocator _get_Container_allocator() const
        { return _Container_allocator(_allocator); }
    inline _Link_allocator _get_Link_allocator() const
        { return _Link_allocator(_allocator); }

    // The serializer is responsible for turning a Key into a prefix (dynamic bitset).
    typedef Serializer<Key, Allocator> serializer_type;

    serializer_type _serializer;

    serializer_type& get_serializer()
        { return _serializer; }
    const serializer_type& get_serializer() const
        { return _serializer; }

public:
    // Internal structures
    typedef typename _Container_allocator::value_type container_type;
    typedef typename _Node_allocator::value_type node_type;
    typedef typename _Link_allocator::value_type link_type;
    typedef CPrefixCompressor<_unsigned_char_allocator> prefix_compressor;
    typedef typename prefix_compressor::prefix_type prefix_type;

    typedef typename _Key_allocator::value_type key_type;
    typedef typename _Data_allocator::value_type data_type;
    typedef data_type mapped_type; // For compatability with std::map
    typedef typename _Value_allocator::value_type value_type;
    typedef typename _Extra_allocator::value_type extra_type;

    typedef typename _Value_allocator::reference reference;
    typedef typename _Value_allocator::const_reference const_reference;
    typedef typename _Value_allocator::pointer pointer;
    typedef typename _Value_allocator::const_pointer const_pointer;

    // FIXME: How do we implement iterators here? There's significant tooling
    //        in the standard library for implementing iterators for STL-like
    //        containers. See <iterator>, for example. We should make use of
    //        that. Obviously what is here right now won't work, but will get
    //        the stub methods to compile.
    typedef node_type* iterator;
    typedef const node_type* const_iterator;
    typedef node_type* reverse_iterator;
    typedef const node_type* const_reverse_iterator;

    // key_comapre ?
    // value_compare ?

protected:
    static node_type SENTINAL;

    node_type _root;
    node_type* _first;
    node_type* _last;

public:
    CHashMap()
        : _allocator(allocator_type())
        , _serializer(serializer_type())
        , _root(), _first(0), _last(0) {}

    explicit CHashMap(const allocator_type& allocatorIn)
        : _allocator(allocatorIn)
        , _serializer(serializer_type())
        , _root(), _first(0), _last(0) {}

    explicit CHashMap(const serializer_type& serializerIn,
                      const allocator_type& allocatorIn = allocator_type())
        : _serializer(serializerIn)
        , _allocator(allocatorIn)
        , _root(), _first(0), _last(0) {}

    template<class InputIterator>
    CHashMap(InputIterator first, InputIterator last,
             const allocator_type& allocatorIn = allocator_type());

    template<class InputIterator>
    CHashMap(InputIterator first, InputIterator last,
             const serializer_type& serializerIn,
             const allocator_type& allocatorIn = allocator_type());

    CHashMap(const container_type& x,
             const allocator_type& allocatorIn = allocator_type());

    CHashMap(const container_type& x,
             const serializer_type& serializerIn,
             const allocator_type& allocatorIn = allocator_type());

    ~CHashMap() { /* FIXME */ }

    container_type& operator=(const container_type& x);

    void swap(container_type& x);

    void clear() throw();

protected:
    bool _GetNodeByKey(const prefix_type& key, prefix_type& prefix, const node_type*& pnode) const
    {
        prefix.clear();
        pnode = &_root;
        while (prefix.size() < key.size())
        {
            const link_type* link;
            if (!key[prefix.size()]) link = pnode->left;
            else                     link = pnode->right;
            if (!link)
                return false;
            typename prefix_type::size_type itr, pos;
            for (itr = 0, pos = prefix.size(); itr != link->prefix.size(); ++pos, ++itr)
            {
                if (pos == key.size())
                    return true;
                if (key[pos] != link->prefix[itr])
                    return false;
            }
            if (link->IsPruned())
                return false;
            for (itr = 0; itr != link->prefix.size(); ++itr)
                prefix.push_back(link->prefix[itr]);
            pnode = link->node;
        }
        return true;
    }

public:
    // Element access
    reference front()
        { return _first? _first->value: SENTINAL; }
    const_reference front() const
        { return _first? _first->value: SENTINAL; }
    const_reference cfront() const
        { return _first? _first->value: SENTINAL; }

    reference back()
        { return _last? _last->value: SENTINAL; }
    const_reference back() const
        { return _last? _last->value: SENTINAL; }
    const_reference cback() const
        { return _last? _last->value: SENTINAL; }

    data_type& operator[](const key_type& k);

    data_type& at(const key_type& k);
    const data_type& at(const key_type& k) const;

    // Iterators
    iterator begin() throw();
    const_iterator begin() const throw();
    iterator end() throw();
    const_iterator end() const throw();

    reverse_iterator rbegin() throw();
    const_reverse_iterator rbegin() const throw();
    reverse_iterator rend() throw();
    const_reverse_iterator rend() const throw();

    const_iterator cbegin() const throw();
    const_iterator cend() const throw();
    const_reverse_iterator crbegin() const throw();
    const_reverse_iterator crend() const throw();

    // Capacity
    bool empty() const
        { return !_root.GetLength(); }

    size_type size() const
        { return _root.GetLength(); }

    size_type max_size() const
        { return std::numeric_limits<size_type>::max(); }

    // Modifiers: insert
    std::pair<iterator,bool> insert(const value_type& val);
    iterator insert(const_iterator position, const value_type& val);

    template <class InputIterator>
    void insert(InputIterator first, InputIterator last);

    // Modifiers: erase
    iterator erase(const_iterator position);
    size_type erase(const key_type& k);
    iterator erase(const_iterator first, const_iterator last);

    // Modifiers: prune
    //
    // Like erase(), but marks the values as pruned and deallocates storage,
    // triming branches as necessary, but does not modify root hash of the
    // tree.
    iterator prune(const_iterator position);
    size_type prune(const key_type& k);
    iterator prune(const_iterator first, const_iterator last);

    // Modifiers: trim
    //
    // Trims any value beginning with the specified prefix.
    iterator trim(const_iterator position);
    size_type trim(const key_type& k);
    size_type trim(const prefix_type& p);

    // Operations
    iterator find(const key_type& k);
    const_iterator find(const key_type& k) const;

    size_type count(const key_type& k) const;

    iterator lower_bound(const key_type& k);
    const_iterator lower_bound(const key_type& k) const;

    iterator upper_bound(const key_type& k);
    const_iterator upper_bound(const key_type& k) const;

    std::pair<iterator,iterator> equal_range(const key_type& k);
    std::pair<const_iterator,const_iterator> equal_range(const key_type& k) const;

public:
    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        return _root.GetSerializeSize(nType, nVersion);
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        _root.Serialize(s, nType, nVersion);
    }

    template<typename Stream>
    void Unserialize(Stream&s, int nType, int nVersion)
    {
        std::pair<node_type*, node_type*> minmax =
            _root.Unserialize(s, nType, nVersion, *this, 0, false);
        _first = minmax.first;
        _last = minmax.second;
    }

public:
    // The non-const version will cache hash values that have to be
    // recalculated:
    uint224 GetHash()
        { return _root.GetHash(); }
    uint224 GetHash() const
        { return _root.GetHash(); }

    struct stats_type
    {
        prefix_type prefix;
        extra_type  extra;
        size_type   length;
        size_type   count;
        size_type   size;

        stats_type()
            : prefix()
            , extra(0, 0, 0)
            , length(0)
            , count(0)
            , size(1) {}

        stats_type(const stats_type& other)
            : prefix(other.prefix)
            , extra(other.extra)
            , length(other.length)
            , count(other.count)
            , size(other.size) {}

        stats_type(const prefix_type& prefixIn, const extra_type& extraIn, size_type lengthIn, size_type countIn, size_type sizeIn)
            : prefix(prefixIn)
            , extra(extraIn)
            , length(lengthIn)
            , count(countIn)
            , size(sizeIn) {}
    };

    bool GetStats(stats_type& stats) const
    {
        stats.prefix = prefix_type();
        stats.extra  = _root.extra;
        stats.length = _root.GetLength();
        stats.count  = _root.GetCount();
        stats.size   = _root.GetSize();
        return true;
    }

    bool GetStats(const prefix_type& prefix, stats_type& stats) const
    {
        const node_type* pnode;
        bool fInTree = _GetNodeByKey(prefix, stats.prefix, pnode);
        if (fInTree) {
            if (prefix.size() > stats.prefix.size()) {
                if (!prefix[stats.prefix.size()]) {
                    fInTree = pnode->left->GetExtra(*pnode, false, stats.extra);
                    stats.length = pnode->left->GetLength();
                    stats.count  = pnode->left->GetCount();
                    stats.size   = pnode->left->GetSize();
                } else {
                    fInTree = pnode->right->GetExtra(*pnode, true, stats.extra);
                    stats.length = pnode->right->GetLength();
                    stats.count  = pnode->right->GetCount();
                    stats.size   = pnode->right->GetSize();
                }
            } else {
                stats.extra  = pnode->extra;
                stats.length = pnode->GetLength();
                stats.count  = pnode->GetCount();
                stats.size   = pnode->GetSize();
            }
        } else {
            stats.extra  = extra_type(0, 0, 0);
            stats.length = 0;
            stats.count  = 0;
            stats.size   = 0;
        }
        return fInTree;
    }
};

template<
    typename Key,
    typename Data,
    typename Extra,
    typename Patricia,
    typename deLaBrandais,
    template<typename _Key, typename Allocator>
        class Serializer,
    typename Allocator>
typename CHashMap<Key,Data,Extra,Patricia,deLaBrandais,Serializer,Allocator>::node_type
    CHashMap<Key,Data,Extra,Patricia,deLaBrandais,Serializer,Allocator>::SENTINAL =
        typename CHashMap<Key,Data,Extra,Patricia,deLaBrandais,Serializer,Allocator>::node_type();

#endif
