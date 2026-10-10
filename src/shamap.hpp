// catl — an in-memory, canonical, incrementally hashed SHAMap.
//
// The tree shape is a pure function of the key set (as in xahaud): the root
// is always an inner node; a key lives as a leaf at the shallowest depth
// where its nibble path is unique; inner nodes below the root always hold
// >= 2 leaves (a lone leaf is pulled up on delete, cf. SHAMap::delItem /
// onlyBelow). Inner hash = SHA512Half('MIN\0' || 16 child hashes, zero for
// empty), empty map hash = 0. Leaf hashes:
//   account state : SHA512Half('MLN\0' || data || key)
//   tx + metadata : SHA512Half('SND\0' || data || key)
//   tx, no meta   : SHA512Half('TXN\0' || data)
// Only nodes on modified paths are re-hashed, so applying a ledger's
// delta to a multi-million-entry state map costs microseconds.
#pragma once

#include "sha.hpp"
#include "util.hpp"

namespace catl {

class SHAMap
{
public:
    enum class Kind : u8 { State, TxMeta, TxNoMeta };

    struct Leaf;
    struct Node
    {
        bool leaf;
        bool dirty = true;
        H256 hash;
    };
    struct Leaf : Node
    {
        H256 key;
        u32 len = 0;
        u8* data = nullptr;
        ByteView
        view() const
        {
            return {data, len};
        }
    };
    struct Inner : Node
    {
        std::array<Node*, 16> kids{};
    };

    explicit SHAMap(Kind k = Kind::State);
    ~SHAMap();
    SHAMap(SHAMap const&) = delete;
    SHAMap&
    operator=(SHAMap const&) = delete;
    SHAMap(SHAMap&& o) noexcept;
    SHAMap&
    operator=(SHAMap&& o) noexcept;

    enum class Upsert { Inserted, Replaced, Unchanged };
    Upsert
    upsert(H256 const& key, u8 const* data, std::size_t n);
    bool
    remove(H256 const& key);
    Leaf const*
    find(H256 const& key) const;
    H256
    rootHash();
    std::size_t
    size() const
    {
        return count_;
    }
    u64
    dataBytes() const
    {
        return bytes_;
    }
    void
    clear();
    Kind
    kind() const
    {
        return kind_;
    }

    // In key order
    template <class F>
    void
    forEach(F&& f) const
    {
        walk(root_, f);
    }

private:
    template <class F>
    static void
    walk(Node const* n, F& f)
    {
        if (!n)
            return;
        if (n->leaf)
        {
            f(*static_cast<Leaf const*>(n));
            return;
        }
        for (Node const* k : static_cast<Inner const*>(n)->kids)
            walk(k, f);
    }
    Leaf*
    makeLeaf(H256 const& key, u8 const* data, std::size_t n);
    void
    setData(Leaf* l, u8 const* data, std::size_t n);
    static void
    destroy(Node* n);
    H256 const&
    hashNode(Node* n);

    Kind kind_;
    Inner* root_;
    std::size_t count_ = 0;
    u64 bytes_ = 0;
};

}  // namespace catl
