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

typedef stealth_incremental_witness<29> incremental_witness;
typedef stealth_incremental_merkle_tree<29> merkle_tree;
typedef stealth_incremental_witness<4> test_incremental_witness;
typedef stealth_incremental_merkle_tree<4> test_merkle_tree;

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

typedef unsigned long long uint64;

const unsigned char G1_PREFIX_MASK = 0x02;
const unsigned char G2_PREFIX_MASK = 0x0a;

// Element in the base field
struct Fq
{
    fc::uint256 data;

    template<typename libsnark_Fq>
    Fq(libsnark_Fq element);

    template<typename libsnark_Fq>
    libsnark_Fq to_libsnark_fq() const;
};

// Element in the extension field
struct Fq2
{
    fc::uint256 data;

    template<typename libsnark_Fq2>
    Fq2(libsnark_Fq2 element);

    template<typename libsnark_Fq2>
    libsnark_Fq2 to_libsnark_fq2() const;
};

// Compressed point in G1
struct CompressedG1
{
    bool y_lsb;
    Fq x;

    CompressedG1() : y_lsb(false), x() { }

    template<typename libsnark_G1>
    CompressedG1(libsnark_G1 point);

    template<typename libsnark_G1>
    libsnark_G1 to_libsnark_g1() const;
};

// Compressed point in G2
struct CompressedG2
{
    bool y_gt;
    Fq2 x;

    CompressedG2() : y_gt(false), x() { }

    template<typename libsnark_G2>
    CompressedG2(libsnark_G2 point);

    template<typename libsnark_G2>
    libsnark_G2 to_libsnark_g2() const;
};

struct stealth_proof
{
    CompressedG1 g_A;
    CompressedG1 g_A_prime;
    CompressedG2 g_B;
    CompressedG1 g_B_prime;
    CompressedG1 g_C;
    CompressedG1 g_C_prime;
    CompressedG1 g_K;
    CompressedG1 g_H;

    // Produces a compressed proof using a libsnark zkSNARK proof
    template<typename libsnark_proof>
    stealth_proof(const libsnark_proof& proof);

    // Produces a libsnark zkSNARK proof out of this proof,
    // or throws an exception if it is invalid.
    template<typename libsnark_proof>
    libsnark_proof to_libsnark_proof() const;

    static stealth_proof random_invalid();
};

struct stealth_joinsplit
{
    static stealth_joinsplit* generate();
    static stealth_joinsplit* unopened();

    static fc::uint256 h_sig(const fc::uint256& random_seed,
                             const boost::array<fc::uint256, 2>& nullifiers,
                             const fc::uint256& public_key_hash);

    virtual stealth_proof prove(
        const boost::array<stealth_input, 2>& inputs,
        const boost::array<stealth_output, 2>& outputs,
        boost::array<stealth_note, 2>& out_notes,
        boost::array<binary, 2>& out_ciphertexts,
        fc::ecc::public_key& out_ephemeral_key,
        const fc::uint256& public_key_hash,
        fc::uint256& out_random_seed,
        boost::array<fc::uint256, 2>& out_hmacs,
        boost::array<fc::uint256, 2>& out_nullifiers,
        boost::array<fc::uint256, 2>& out_commitments,
        uint64 vpub_old,
        uint64 vpub_new,
        const fc::uint256& rt,
        bool compute_proof = true
    ) = 0;

    virtual bool verify(
        const stealth_proof& proof,
        const fc::uint256& public_key_hash,
        const fc::uint256& random_seed,
        const boost::array<fc::uint256, 2>& hmacs,
        const boost::array<fc::uint256, 2>& nullifiers,
        const boost::array<fc::uint256, 2>& commitments,
        uint64 vpub_old,
        uint64 vpub_new,
        const fc::uint256& rt
    ) = 0;
};

struct stealth_transfer_operation : public base_operation
{
   asset fee;
   boost::array<stealth_input, 2> inputs;
   boost::array<stealth_output, 2> outputs;

   static stealth_transfer_operation Generate();
   static stealth_transfer_operation Unopened();
   static fc::uint256 h_sig(const fc::uint256& random_seed,
                        const boost::array<fc::uint256, 2>& nullifiers,
                        const fc::uint256& public_key_hash
                       );

   stealth_proof prove(
       const boost::array<stealth_input, 2>& inputs,
       const boost::array<stealth_output, 2>& outputs,
       boost::array<stealth_note, 2>& notes,
       boost::array<binary, 2>& ciphertexts,
       fc::uint256& ephemeral_key,
       const fc::uint256& public_key_hash,
       fc::uint256& random_seed,
       boost::array<fc::uint256, 2>& hmacs,
       boost::array<fc::uint256, 2>& nullifiers,
       boost::array<fc::uint256, 2>& commitments,
       uint64 vpub_old,
       uint64 vpub_new,
       const fc::uint256& nullifier_base,
       bool compute_proof = true
   );

   bool verify(
       const stealth_proof& proof,
       const fc::uint256& public_key_hash,
       const fc::uint256& random_seed,
       const boost::array<fc::uint256, 2>& hmacs,
       const boost::array<fc::uint256, 2>& nullifiers,
       const boost::array<fc::uint256, 2>& commitments,
       uint64 vpub_old,
       uint64 vpub_new,
       const fc::uint256& nullifier_base
   );
   /** graphene TEMP account */
   account_id_type fee_payer()const;
   void            validate()const;
   share_type      calculate_fee()const;
};

}}

FC_REFLECT( graphene::chain::stealth_payment_address, (paying_key)(transmission_key) );
FC_REFLECT( graphene::chain::stealth_viewing_key, (value));
FC_REFLECT( graphene::chain::stealth_spending_key, (value));
FC_REFLECT( graphene::chain::stealth_note, (paying_key)(amount)(nullifier_base)(trapdoor));
FC_REFLECT( graphene::chain::stealth_note_plaintext, (amount)(nullifier_base)(trapdoor)(memo));
