// catl — SHAMap implementation (see shamap.hpp for the invariants)
#include "shamap.hpp"

namespace catl {

SHAMap::SHAMap(Kind k) : kind_(k), root_(new Inner)
{
    root_->leaf = false;
}

SHAMap::~SHAMap()
{
    destroy(root_);
}

SHAMap::SHAMap(SHAMap&& o) noexcept : kind_(o.kind_), root_(o.root_), count_(o.count_), bytes_(o.bytes_)
{
    o.root_ = new Inner;
    o.root_->leaf = false;
    o.count_ = 0;
    o.bytes_ = 0;
}

SHAMap&
SHAMap::operator=(SHAMap&& o) noexcept
{
    if (this != &o)
    {
        std::swap(kind_, o.kind_);
        std::swap(root_, o.root_);
        std::swap(count_, o.count_);
        std::swap(bytes_, o.bytes_);
        o.clear();
    }
    return *this;
}

void
SHAMap::destroy(Node* n)
{
    if (!n)
        return;
    if (n->leaf)
    {
        auto* l = static_cast<Leaf*>(n);
        delete[] l->data;
        delete l;
        return;
    }
    auto* in = static_cast<Inner*>(n);
    for (Node* k : in->kids)
        destroy(k);
    delete in;
}

void
SHAMap::clear()
{
    destroy(root_);
    root_ = new Inner;
    root_->leaf = false;
    count_ = 0;
    bytes_ = 0;
}

SHAMap::Leaf*
SHAMap::makeLeaf(H256 const& key, u8 const* data, std::size_t n)
{
    auto* l = new Leaf;
    l->leaf = true;
    l->key = key;
    setData(l, data, n);
    return l;
}

void
SHAMap::setData(Leaf* l, u8 const* data, std::size_t n)
{
    if (l->len != n || !l->data)
    {
        bytes_ -= l->len;
        delete[] l->data;
        l->data = n ? new u8[n] : nullptr;
        l->len = u32(n);
        bytes_ += n;
    }
    if (n)
        std::memcpy(l->data, data, n);
    l->dirty = true;
}

SHAMap::Upsert
SHAMap::upsert(H256 const& key, u8 const* data, std::size_t n)
{
    Inner* node = root_;
    int depth = 0;
    for (;;)
    {
        node->dirty = true;
        int nib = key.nibble(depth);
        Node*& slot = node->kids[std::size_t(nib)];
        if (!slot)
        {
            slot = makeLeaf(key, data, n);
            ++count_;
            return Upsert::Inserted;
        }
        if (!slot->leaf)
        {
            node = static_cast<Inner*>(slot);
            ++depth;
            continue;
        }
        auto* existing = static_cast<Leaf*>(slot);
        if (existing->key == key)
        {
            if (existing->len == n && (n == 0 || std::memcmp(existing->data, data, n) == 0))
                return Upsert::Unchanged;
            setData(existing, data, n);
            return Upsert::Replaced;
        }
        // split: push inner nodes down until the two keys diverge
        int d = depth + 1;
        auto* chainTop = new Inner;
        chainTop->leaf = false;
        Inner* cur = chainTop;
        while (key.nibble(d) == existing->key.nibble(d))
        {
            auto* next = new Inner;
            next->leaf = false;
            cur->kids[std::size_t(key.nibble(d))] = next;
            cur = next;
            ++d;
        }
        cur->kids[std::size_t(existing->key.nibble(d))] = existing;
        cur->kids[std::size_t(key.nibble(d))] = makeLeaf(key, data, n);
        slot = chainTop;
        ++count_;
        return Upsert::Inserted;
    }
}

bool
SHAMap::remove(H256 const& key)
{
    Inner* path[65];
    int nibs[65];
    int depth = 0;
    Inner* node = root_;
    for (;;)
    {
        int nib = key.nibble(depth);
        Node* slot = node->kids[std::size_t(nib)];
        if (!slot)
            return false;
        path[depth] = node;
        nibs[depth] = nib;
        if (slot->leaf)
        {
            auto* l = static_cast<Leaf*>(slot);
            if (l->key != key)
                return false;
            bytes_ -= l->len;
            delete[] l->data;
            delete l;
            node->kids[std::size_t(nib)] = nullptr;
            --count_;
            break;
        }
        node = static_cast<Inner*>(slot);
        ++depth;
    }
    for (int d = 0; d <= depth; ++d)
        path[d]->dirty = true;
    // collapse: a non-root inner node left holding a single leaf (and
    // nothing else) is replaced by that leaf, repeatedly up the path
    for (int d = depth; d > 0; --d)
    {
        Inner* in = path[d];
        Node* only = nullptr;
        int cnt = 0;
        for (Node* k : in->kids)
            if (k)
            {
                ++cnt;
                only = k;
            }
        if (cnt == 0)
        {
            // cannot happen for a canonical tree, but keep it tidy
            path[d - 1]->kids[std::size_t(nibs[d - 1])] = nullptr;
            delete in;
            continue;
        }
        if (cnt == 1 && only->leaf)
        {
            path[d - 1]->kids[std::size_t(nibs[d - 1])] = only;
            delete in;
            continue;
        }
        break;
    }
    return true;
}

SHAMap::Leaf const*
SHAMap::find(H256 const& key) const
{
    Node const* n = root_;
    int depth = 0;
    while (n && !n->leaf)
        n = static_cast<Inner const*>(n)->kids[std::size_t(key.nibble(depth++))];
    if (!n)
        return nullptr;
    auto const* l = static_cast<Leaf const*>(n);
    return l->key == key ? l : nullptr;
}

H256 const&
SHAMap::hashNode(Node* n)
{
    if (!n->dirty)
        return n->hash;
    Sha512 s;
    if (n->leaf)
    {
        auto* l = static_cast<Leaf*>(n);
        switch (kind_)
        {
            case Kind::State:
                s.updateBE32(kPrefixLeaf);
                s.update(l->data, l->len);
                s.update(l->key);
                break;
            case Kind::TxMeta:
                s.updateBE32(kPrefixTxNode);
                s.update(l->data, l->len);
                s.update(l->key);
                break;
            case Kind::TxNoMeta:
                s.updateBE32(kPrefixTxId);
                s.update(l->data, l->len);
                break;
        }
        l->hash = s.finalHalf();
    }
    else
    {
        auto* in = static_cast<Inner*>(n);
        bool any = false;
        u8 buf[4 + 16 * 32] = {};
        putBE32(buf, kPrefixInner);
        for (int i = 0; i < 16; ++i)
            if (in->kids[std::size_t(i)])
            {
                any = true;
                std::memcpy(buf + 4 + 32 * i, hashNode(in->kids[std::size_t(i)]).data(), 32);
            }
        if (any)
        {
            s.update(buf, sizeof buf);
            in->hash = s.finalHalf();
        }
        else
            in->hash = H256{};
    }
    n->dirty = false;
    return n->hash;
}

H256
SHAMap::rootHash()
{
    return hashNode(root_);
}

}  // namespace catl
