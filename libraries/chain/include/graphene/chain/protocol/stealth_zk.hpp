/*
 * Copyright (c) 2016 Cryptonomex, Inc., and contributors.
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#pragma once
#include <graphene/chain/protocol/base.hpp>
#include <fc/crypto/elliptic.hpp>
#include <boost/array.hpp>
#include <boost/optional.hpp>

namespace graphene { namespace chain {

#define STEALTH_MEMO_SIZE 256
typedef std::vector<char> binary;

fc::uint256 random_uint256();
binary random_binary(size_t size);
fc::uint256 combine256(const fc::uint256 &v1, const fc::uint256 &v2);
std::vector<unsigned char> convert_int_to_bytes_vector(const u_int64_t& val_int);
std::vector<bool> convert_bytes_vector_to_bool_vector(const std::vector<unsigned char>& bytes);
u_int64_t convert_bool_vector_to_int(const std::vector<bool>& v);
std::vector<bool> convert_int_to_bool_vector(const u_int64_t& val_int);
std::vector<bool> convert_uint256_to_bool_vector(const fc::uint256& val);
void insert_uint256(std::vector<bool>& into, fc::uint256 from);
void insert_uint64(std::vector<bool>& into, u_int64_t from);

struct stealth_payment_address
{
    fc::uint256 paying_key;
    fc::ecc::public_key transmission_key;

    fc::uint256 hash() const;
};

struct stealth_viewing_key
{
    fc::ecc::private_key value;

    fc::ecc::public_key transmission_key() const;
};

struct stealth_spending_key
{
    fc::ecc::private_key value;

    static stealth_spending_key random();

    stealth_viewing_key viewing_key() const;
    stealth_payment_address address() const;
};

struct stealth_note
{
    fc::uint256 paying_key;
    asset amount;
    fc::uint256 nullifier_base;
    fc::uint256 trapdoor;

    stealth_note();
    stealth_note(const fc::uint256& p_k, const asset& a,
                 const fc::uint256& n_b, const fc::uint256& t);

    fc::uint256 commitment() const;
    fc::uint256 nullifier(const stealth_spending_key& a_sk) const;
};


struct stealth_note_decryption
{
    fc::ecc::private_key secret_key;
    fc::ecc::public_key public_key;

    stealth_note_decryption(fc::ecc::private_key secret_key);

    binary decrypt(const binary &ciphertext,
                      const fc::ecc::public_key &ephemeral_public_key,
                      const fc::uint256 &h_sig,
                      unsigned char nonce
                     ) const;
};

struct stealth_note_encryption
{
    fc::ecc::public_key ephemeral_public_key;
    fc::ecc::private_key ephemeral_secret_key;
    unsigned char nonce;
    fc::uint256 h_sig;

    stealth_note_encryption(fc::uint256 h_sig);

    binary encrypt(const fc::ecc::public_key& encryption_public_key,
                                  const binary& plaintext);

    static fc::ecc::private_key generate_secret_key(const stealth_spending_key &spending_key);
    static fc::ecc::public_key generate_public_key(const fc::ecc::private_key &secret_key);
};

struct stealth_note_plaintext
{
    asset amount;
    fc::uint256 nullifier_base;
    fc::uint256 trapdoor;
    binary memo;

    stealth_note_plaintext();
    stealth_note_plaintext(const stealth_note& note, const binary& memo);

    stealth_note note(const stealth_payment_address& address) const;

    static stealth_note_plaintext decrypt(
                                 const stealth_note_decryption& decryptor,
                                 const binary& ciphertext,
                                 const fc::ecc::public_key& ephemeral_key,
                                 const fc::uint256& h_sig,
                                 unsigned char nonce
                                );

    binary encrypt(stealth_note_encryption& encryptor,
                   const fc::ecc::public_key& transmission_key) const;
};

struct stealth_merkle_path
{
    std::vector<std::vector<bool>> authentication_path;
    std::vector<bool> index;

    stealth_merkle_path() {}
    stealth_merkle_path(std::vector<std::vector<bool>> ap, std::vector<bool> i):
        authentication_path(ap), index(i) {}
};

template<size_t Depth>
class stealth_empty_merkle_roots {
public:
    stealth_empty_merkle_roots() {
        empty_roots.at(0) = fc::uint256();
        for (size_t d = 1; d <= Depth; d++)
            empty_roots.at(d) = combine256(empty_roots.at(d-1), empty_roots.at(d-1));
    }
    fc::uint256 empty_root(size_t depth) {
        return empty_roots.at(depth);
    }
    template <size_t D>
    friend bool operator==(const stealth_empty_merkle_roots<D>& a,
                           const stealth_empty_merkle_roots<D>& b);
private:
    boost::array<fc::uint256, Depth+1> empty_roots;
};

template<size_t Depth>
bool operator==(const stealth_empty_merkle_roots<Depth>& a,
                const stealth_empty_merkle_roots<Depth>& b) {
    return a.empty_roots == b.empty_roots;
}

template<size_t Depth>
struct stealth_incremental_witness;

template<size_t Depth>
struct stealth_incremental_merkle_tree
{
    friend struct stealth_incremental_witness<Depth>;
    template <size_t D>
    friend bool operator==(const stealth_incremental_merkle_tree<D>& a,
                           const stealth_incremental_merkle_tree<D>& b);

    fc::uint256 root();
    void append(fc::uint256 hash);
    stealth_incremental_witness<Depth> witness() const;
    static fc::uint256 empty_root();
private:
    static stealth_empty_merkle_roots<Depth> emptyroots;
    boost::optional<fc::uint256> left;
    boost::optional<fc::uint256> right;

    // Collapsed "left" subtrees ordered toward the root of the tree.
    std::vector<boost::optional<fc::uint256>> parents;
    stealth_merkle_path path(
            std::deque<fc::uint256> filler_hashes = std::deque<fc::uint256>()) const;
    fc::uint256 root(size_t depth,
                     std::deque<fc::uint256> filler_hashes = std::deque<fc::uint256>()) const;
    bool is_complete(size_t depth = Depth) const;
    size_t next_depth(size_t skip) const;
};

template<size_t Depth>
bool operator==(const stealth_incremental_merkle_tree<Depth>& a,
                const stealth_incremental_merkle_tree<Depth>& b) {
    return (a.emptyroots == b.emptyroots &&
            a.left == b.left &&
            a.right == b.right &&
            a.parents == b.parents);
}


template<size_t Depth>
struct stealth_incremental_witness
{
    friend struct stealth_incremental_merkle_tree<Depth>;
    template <size_t D>
    friend bool operator==(const stealth_incremental_witness<D>& a,
                           const stealth_incremental_witness<D>& b);

    stealth_incremental_witness() {}

    stealth_merkle_path path() const;
    fc::uint256 root() const;
    void append(fc::uint256 obj);

private:
    stealth_incremental_merkle_tree<Depth> tree;
    std::vector<fc::uint256> filled;
    boost::optional<stealth_incremental_merkle_tree<Depth>> cursor;
    size_t cursor_depth = 0;
    std::deque<fc::uint256> partial_path() const;
    stealth_incremental_witness(stealth_incremental_merkle_tree<Depth> t) : tree(t) {}
};

template<size_t Depth>
bool operator==(const stealth_incremental_witness<Depth>& a,
                const stealth_incremental_witness<Depth>& b) {
    return (a.tree == b.tree &&
            a.filled == b.filled &&
            a.cursor == b.cursor &&
            a.cursor_depth == b.cursor_depth);
}

#define INCREMENTAL_MERKLE_TREE_DEPTH 29
#define INCREMENTAL_TEST_MERKLE_TREE_DEPTH 4
typedef stealth_incremental_witness<INCREMENTAL_MERKLE_TREE_DEPTH> incremental_witness;
typedef stealth_incremental_merkle_tree<INCREMENTAL_MERKLE_TREE_DEPTH> merkle_tree;
typedef stealth_incremental_witness<INCREMENTAL_TEST_MERKLE_TREE_DEPTH> test_incremental_witness;
typedef stealth_incremental_merkle_tree<INCREMENTAL_TEST_MERKLE_TREE_DEPTH> test_merkle_tree;

struct stealth_input
{
    incremental_witness witness;
    stealth_note note;
    stealth_spending_key spending_key;

    fc::uint256 nullifier() const;

    stealth_input() {}
    stealth_input(incremental_witness w, stealth_note n,
                  stealth_spending_key sk) :
        witness(w), note(n), spending_key(sk) {}
};

struct stealth_output
{
    stealth_payment_address address;
    asset value;
    binary memo;

    stealth_output() {}
    stealth_output(stealth_payment_address a, asset v) : address(a), value(v){}

    stealth_note note(const fc::uint256& phi,
                      const fc::uint256& trapdoor, size_t i,
                      const fc::uint256& h_sig) const;
};


struct stealth_transfer_operation : public base_operation
{
   asset fee;

   /** graphene TEMP account */
   account_id_type fee_payer()const;
   void            validate()const;
   share_type      calculate_fee()const;
   asset fee2;
};

}}

FC_REFLECT( graphene::chain::stealth_payment_address, (paying_key)(transmission_key) );
FC_REFLECT( graphene::chain::stealth_viewing_key, (value));
FC_REFLECT( graphene::chain::stealth_spending_key, (value));
FC_REFLECT( graphene::chain::stealth_note, (paying_key)(amount)(nullifier_base)(trapdoor));
FC_REFLECT( graphene::chain::stealth_note_plaintext, (amount)(nullifier_base)(trapdoor)(memo));
