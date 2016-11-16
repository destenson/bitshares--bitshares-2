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
#include <boost/array.hpp>

namespace graphene { namespace chain {

struct stealth_payment_address
{
    fc::uint256 paying_key;
    fc::uint256 transmission_key;

    fc::uint256 hash() const;
};

struct stealth_viewing_key
{
    fc::uint256 value;

    fc::uint256 transmission_key() const;
};

struct stealth_spending_key
{
    fc::uint256 value;

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
    fc::uint256 commitment() const;
    fc::uint256 nullifier(const stealth_spending_key& a_sk) const;
};


#define STEALTH_MEMO_SIZE 256
typedef boost::array<unsigned char, STEALTH_MEMO_SIZE> stealth_memo;
typedef std::vector<unsigned char> binary;

struct stealth_note_decryption
{
    fc::uint256 secret_key;
    fc::uint256 public_key;

    stealth_note_decryption(fc::uint256 secret_key);

    binary decrypt(const binary &ciphertext,
                      const fc::uint256 &ephemeral_public_key,
                      const fc::uint256 &h_sig,
                      unsigned char nonce
                     ) const;
};

struct stealth_note_encryption
{
    fc::uint256 ephemeral_public_key;
    fc::uint256 ephemeral_secret_key;
    unsigned char nonce;
    fc::uint256 h_sig;

    stealth_note_encryption(fc::uint256 h_sig);

    binary encrypt(const fc::uint256& encryption_public_key,
                                  const binary& plaintext);

    static fc::uint256 generate_secret_key(const stealth_spending_key &paying_key);
    static fc::uint256 generate_public_key(const fc::uint256 &secret_key);
};

struct stealth_note_plaintext
{
    asset amount;
    fc::uint256 nullifier_base;
    fc::uint256 trapdoor;
    stealth_memo memo;

    stealth_note_plaintext(const stealth_note& note, const stealth_memo& memo);

    stealth_note note(const stealth_payment_address& address) const;

    static stealth_note_plaintext decrypt(
                                 const stealth_note_decryption& decryptor,
                                 const binary& ciphertext,
                                 const fc::uint256& ephemeral_key,
                                 const fc::uint256& h_sig,
                                 unsigned char nonce
                                );

    binary encrypt(stealth_note_encryption& encryptor,
                                  const fc::uint256& transmission_key) const;
};

struct stealth_input
{
    stealth_note note;
    stealth_spending_key spending_key;

    fc::uint256 nullifier() const;
};

struct stealth_output
{
    stealth_payment_address address;
    asset value;
    stealth_memo memo;

    stealth_note note(const fc::uint256& nullifier_base,
                      const fc::uint256& trapdoor, size_t i,
                      const fc::uint256& h_sig) const;
};

typedef unsigned long long uint64;

struct stealth_proof
{

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
