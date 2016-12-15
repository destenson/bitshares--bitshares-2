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
#include <graphene/chain/protocol/stealth_zk.hpp>
#include <graphene/chain/database.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/crypto/dh.hpp>
#include <fc/crypto/aes.hpp>

#include <array>

namespace graphene { namespace chain {

/////////////////////////////////////////////////////////////
// helper functions
/////////////////////////////////////////////////////////////


fc::uint256 random_uint256()
{
    fc::uint256 ret;
    fc::rand_bytes(ret.data(), ret.data_size());
    return ret;
}

binary random_binary(size_t size)
{
    binary ret(size, 0);
    fc::rand_bytes(ret.data(), ret.size());
    return ret;
}

///////////////////////////////////////////////////////////
// PRF
///////////////////////////////////////////////////////////

fc::uint256 PRF(bool a, bool b, bool c, bool d,
            const fc::uint256& x,
            const fc::uint256& y)
{
    std::array<char, 64> blob;

    memcpy(&blob[0], x.data(), x.data_size());
    memcpy(&blob[32], y.data(), y.data_size());

    blob[0] &= 0x0F;
    blob[0] |= (a ? 1 << 7 : 0) | (b ? 1 << 6 : 0) | (c ? 1 << 5 : 0) | (d ? 1 << 4 : 0);

    return fc::uint256::hash(blob.data(), blob.size());
}

fc::uint256 PRF_addr(const fc::uint256& a_sk, unsigned char t)
{
    fc::uint256 y;
    *y.data() = t;

    return PRF(1, 1, 0, 0, a_sk, y);
}

fc::uint256 PRF_addr_a_pk(const fc::uint256& a_sk)
{
    return PRF_addr(a_sk, 0);
}

fc::uint256 PRF_addr_sk_enc(const fc::uint256& a_sk)
{
    return PRF_addr(a_sk, 1);
}

fc::uint256 PRF_nf(const fc::uint256& a_sk, const fc::uint256& rho)
{
    return PRF(1, 1, 1, 0, a_sk, rho);
}

fc::uint256 PRF_pk(const fc::uint256& a_sk, size_t i0, const fc::uint256& h_sig)
{
    if ((i0 != 0) && (i0 != 1)) {
        throw std::domain_error("PRF_pk invoked with index out of bounds");
    }

    return PRF(0, i0, 0, 0, a_sk, h_sig);
}

fc::uint256 PRF_rho(const fc::uint256& phi, size_t i0, const fc::uint256& h_sig)
{
    if ((i0 != 0) && (i0 != 1)) {
        throw std::domain_error("PRF_rho invoked with index out of bounds");
    }

    return PRF(0, i0, 1, 0, phi, h_sig);
}

//////////////////////////////////////////////////////////////////
// addresses
//////////////////////////////////////////////////////////////////

fc::uint256 stealth_payment_address::hash() const
{
    return fc::sha256::hash(fc::raw::pack( *this ));
}

fc::ecc::public_key stealth_viewing_key::transmission_key() const
{
    return stealth_note_encryption::generate_public_key(value);
}

stealth_spending_key stealth_spending_key::random()
{
    return stealth_spending_key({fc::ecc::private_key::generate()});
}

stealth_viewing_key stealth_spending_key::viewing_key() const
{
    return stealth_viewing_key(
        {stealth_note_encryption::generate_secret_key(*this)}
                );
}

stealth_payment_address stealth_spending_key::address() const
{
    return stealth_payment_address(
        {PRF_addr_a_pk(value), viewing_key().transmission_key()});
}


/////////////////////////////////////////////////////////////////
// note
////////////////////////////////////////////////////////////////

stealth_note::stealth_note():
    paying_key(random_uint256()),
    nullifier_base(random_uint256()),
    trapdoor(random_uint256())
{

}

stealth_note::stealth_note(const fc::uint256 &p_k,
                           const asset &a, const fc::uint256 &n_b,
                           const fc::uint256 &t):
    paying_key(p_k),
    amount(a),
    nullifier_base(n_b),
    trapdoor(t)
{

}

fc::uint256 stealth_note::commitment() const
{
    return fc::sha256::hash(fc::raw::pack( *this ));
}

fc::uint256 stealth_note::nullifier(const stealth_spending_key &a_sk) const
{
    return PRF_nf(a_sk.value, nullifier_base);
}

stealth_note_plaintext::stealth_note_plaintext()
{
}

stealth_note_plaintext::stealth_note_plaintext(const stealth_note &note,
                                               const binary &m):
    amount(note.amount),
    nullifier_base(note.nullifier_base),
    trapdoor(note.trapdoor),
    memo(m)
{

}

stealth_note stealth_note_plaintext::note(
        const stealth_payment_address &address) const
{
    return stealth_note(address.paying_key, amount, nullifier_base,
                         trapdoor);
}

stealth_note_plaintext stealth_note_plaintext::decrypt(
        const stealth_note_decryption &decryptor, const binary &ciphertext,
        const fc::ecc::public_key &ephemeral_key, const binary &h_sig,
        unsigned char nonce)
{
    auto plaintext = decryptor.decrypt(ciphertext, ephemeral_key, h_sig,
                                       nonce);
    return fc::raw::unpack<stealth_note_plaintext>(plaintext);
}

binary stealth_note_plaintext::encrypt(stealth_note_encryption &encryptor,
                                       const fc::ecc::public_key &transmission_key) const
{
    return encryptor.encrypt(transmission_key, fc::raw::pack(*this));
}

//////////////////////////////////////////////////////////////////
// Note encryption/decryption
//////////////////////////////////////////////////////////////////

fc::uint512 KDF(
    const fc::uint256 &dhsecret,
    const fc::ecc::public_key &epk,
    const fc::ecc::public_key &pk_enc,
    const binary &h_sig,
    unsigned char nonce
   )
{
    if (nonce == 0xff) {
        throw std::logic_error("no additional nonce space for KDF");
    }

    fc::sha512::encoder e;
    fc::raw::pack(e, dhsecret);
    fc::raw::pack(e, epk);
    fc::raw::pack(e, pk_enc);
    fc::raw::pack(e, h_sig);
    fc::raw::pack(e, nonce);
    return e.result();
}

stealth_note_encryption::stealth_note_encryption(binary sig) :
    nonce(0),
    h_sig(sig)
{
    // Create the ephemeral keypair
    ephemeral_secret_key = fc::ecc::private_key::generate();
    ephemeral_public_key =
            stealth_note_encryption::generate_public_key(
                ephemeral_secret_key
                );
}

binary stealth_note_encryption::encrypt(const fc::ecc::public_key &encryption_public_key,
                                        const binary &plaintext)
{    
    fc::uint512 shared = ephemeral_secret_key.get_shared_secret(encryption_public_key);
    fc::uint256 dhsecret = fc::sha256::hash(shared);

    // Construct the symmetric key
    fc::uint512 K = KDF(dhsecret, ephemeral_public_key,
                        encryption_public_key,
                        h_sig, nonce);

    // Increment the number of encryptions we've performed
    nonce++;

    binary ciphertext = fc::aes_encrypt(K, plaintext);

    // add checksum to verify integrity
    fc::sha256::encoder e;
    fc::raw::pack(e, K);
    fc::raw::pack(e, ciphertext);
    auto check = e.result();

    ciphertext.insert(ciphertext.end(), check.data(),
                      check.data() + check.data_size());

    return ciphertext;
}

fc::ecc::private_key stealth_note_encryption::generate_secret_key(
        const stealth_spending_key &spending_key)
{
    fc::uint256 sk = PRF_addr_sk_enc(spending_key.value);
    return fc::ecc::private_key::generate_from_seed(sk);
}

fc::ecc::public_key stealth_note_encryption::generate_public_key(
        const fc::ecc::private_key &secret_key)
{
    return secret_key.get_public_key();
}


stealth_note_decryption::stealth_note_decryption(fc::ecc::private_key s_k):
    secret_key(s_k)
{
    public_key = stealth_note_encryption::generate_public_key(secret_key);
}

binary stealth_note_decryption::decrypt(const binary &ciphertext,
                                        const fc::ecc::public_key &ephemeral_public_key,
                                        const binary &h_sig,
                                        unsigned char nonce) const
{
    fc::uint512 shared = secret_key.get_shared_secret(ephemeral_public_key);
    fc::uint256 dhsecret = fc::sha256::hash(shared);

    // Construct the symmetric key
    fc::uint512 K = KDF(dhsecret, ephemeral_public_key,
                       public_key,
        h_sig, nonce);


    binary c(ciphertext);
    // extract checksum
    FC_ASSERT(c.size() > 32);
    auto shift = c.size() - 32;
    fc::sha256 check_orig(c.data() + shift, 32);
    c.erase(c.begin() + shift, c.end());

    fc::sha256::encoder e;
    fc::raw::pack(e, K);
    fc::raw::pack(e, c);
    auto check = e.result();
    if(check != check_orig)
        throw std::runtime_error("Failed to decrypt message");

    return fc::aes_decrypt(K, c);
}

fc::uint256 stealth_input::nullifier() const
{
    return note.nullifier(spending_key);
}

stealth_note stealth_output::note(const fc::uint256 &nullifier_base,
                                  const fc::uint256 &trapdoor, size_t i,
                                  const binary &h_sig) const
{

}

}}

