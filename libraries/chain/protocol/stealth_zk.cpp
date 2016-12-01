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
#include <fc/crypto/blowfish.hpp>
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

fc::uint256 stealth_viewing_key::transmission_key() const
{
    return stealth_note_encryption::generate_public_key(value);
}

stealth_spending_key stealth_spending_key::random()
{
    return stealth_spending_key({random_uint256()});
}

stealth_viewing_key stealth_spending_key::viewing_key() const
{
    return stealth_viewing_key(
        {stealth_note_encryption::generate_secret_key(*this)}
                );
}

stealth_payment_address stealth_spending_key::address() const
{
    return stealth_payment_address({PRF_addr_a_pk(value),
                                    viewing_key().transmission_key()});
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
        const fc::uint256 &ephemeral_key, const fc::uint256 &h_sig,
        unsigned char nonce)
{
    auto plaintext = decryptor.decrypt(ciphertext, ephemeral_key, h_sig,
                                       nonce);
    return fc::raw::unpack<stealth_note_plaintext>(plaintext);
}

binary stealth_note_plaintext::encrypt(stealth_note_encryption &encryptor,
                                       const fc::uint256 &transmission_key) const
{
    return encryptor.encrypt(transmission_key, fc::raw::pack(*this));
}

//////////////////////////////////////////////////////////////////
// Note encryption/decryption
//////////////////////////////////////////////////////////////////

#define NOTEENCRYPTION_CIPHER_KEYSIZE 32


fc::uint256 KDF(
    const fc::uint256 &dhsecret,
    const fc::uint256 &epk,
    const fc::uint256 &pk_enc,
    const fc::uint256 &hSig,
    unsigned char nonce
   )
{
    if (nonce == 0xff) {
        throw std::logic_error("no additional nonce space for KDF");
    }

    boost::array<char, 129> block;
    memcpy(&block[0], hSig.data(), hSig.data_size());
    memcpy(&block[32], dhsecret.data(), dhsecret.data_size());
    memcpy(&block[64], epk.data(), epk.data_size());
    memcpy(&block[96], pk_enc.data(), pk_enc.data_size());
    block[128] = nonce;

    return fc::sha256::hash(block.data(), block.size());
}

stealth_note_encryption::stealth_note_encryption(fc::uint256 sig) :
    nonce(0),
    h_sig(sig)
{
    // Create the ephemeral keypair
    ephemeral_secret_key = random_uint256();
    ephemeral_public_key =
            stealth_note_encryption::generate_public_key(
                ephemeral_secret_key
                );
}

binary stealth_note_encryption::encrypt(const fc::uint256 &encryption_public_key,
                                        const binary &plaintext)
{

    fc::diffie_hellman dh;
    dh.priv_key.assign(ephemeral_secret_key.data(),
                       ephemeral_secret_key.data() +
                       ephemeral_secret_key.data_size());
    dh.generate_pub_key();
    dh.compute_shared_key(encryption_public_key.data(),
                          encryption_public_key.data_size());
    fc::uint256 dhsecret(&dh.shared_key[0],
            dh.shared_key.size()); // TODO: check if it is correct

    // Construct the symmetric key
    fc::uint256 K = KDF(dhsecret, ephemeral_public_key, encryption_public_key,
        h_sig, nonce);

    // Increment the number of encryptions we've performed
    nonce++;

    binary ciphertext(plaintext);

    fc::blowfish bf;
    bf.start(reinterpret_cast<unsigned char*>(K.data()), K.data_size());
    bf.encrypt(reinterpret_cast<unsigned char*>(ciphertext.data()), ciphertext.size());

    return ciphertext;
}

fc::uint256 stealth_note_encryption::generate_secret_key(const stealth_spending_key &paying_key)
{

}

fc::uint256 stealth_note_encryption::generate_public_key(const fc::uint256 &secret_key)
{

}


stealth_note_decryption::stealth_note_decryption(fc::uint256 s_k):
    secret_key(s_k)
{
    public_key = stealth_note_encryption::generate_public_key(secret_key);
}

binary stealth_note_decryption::decrypt(const binary &ciphertext, const fc::uint256 &ephemeral_public_key, const fc::uint256 &h_sig, unsigned char nonce) const
{

}

fc::uint256 stealth_input::nullifier() const
{
    return note.nullifier(spending_key);
}

stealth_note stealth_output::note(const fc::uint256 &nullifier_base,
                                  const fc::uint256 &trapdoor, size_t i,
                                  const fc::uint256 &h_sig) const
{

}

}}

