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
#include <boost/foreach.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

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

fc::uint256 combine256(const fc::uint256& v1, const fc::uint256& v2)
{
    fc::sha256::encoder e;
    fc::raw::pack(e, v1);
    fc::raw::pack(e, v2);
    return e.result();
}


// Convert bytes into boolean vector. (MSB to LSB)
std::vector<bool> convert_bytes_vector_to_vector(const std::vector<unsigned char>& bytes) {
    std::vector<bool> ret;
    ret.resize(bytes.size() * 8);

    unsigned char c;
    for (size_t i = 0; i < bytes.size(); i++) {
        c = bytes.at(i);
        for (size_t j = 0; j < 8; j++) {
            ret.at((i*8)+j) = (c >> (7-j)) & 1;
        }
    }

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

fc::uint256 PRF_pk(const fc::uint256& a_sk, size_t i0,
                   const fc::uint256& h_sig)
{
    if ((i0 != 0) && (i0 != 1)) {
        throw std::domain_error("PRF_pk invoked with index out of bounds");
    }

    return PRF(0, i0, 0, 0, a_sk, h_sig);
}

fc::uint256 PRF_rho(const fc::uint256& phi, size_t i0,
                    const fc::uint256& h_sig)
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
        const fc::ecc::public_key &ephemeral_key, const fc::uint256 &h_sig,
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
    const fc::uint256 &h_sig,
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

stealth_note_encryption::stealth_note_encryption(fc::uint256 sig) :
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
                                        const fc::uint256 &h_sig,
                                        unsigned char nonce) const
{
    fc::uint512 shared = secret_key.get_shared_secret(ephemeral_public_key);
    fc::uint256 dhsecret = fc::sha256::hash(shared);

    // Construct the symmetric key
    fc::uint512 K = KDF(dhsecret, ephemeral_public_key,
                       public_key, h_sig, nonce);


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

stealth_note stealth_output::note(const fc::uint256 &phi,
                                  const fc::uint256 &trapdoor, size_t i,
                                  const fc::uint256 &h_sig) const
{
    fc::uint256 nullifier_base = PRF_rho(phi, i, h_sig);
    return stealth_note(address.paying_key, value, nullifier_base, trapdoor);
}

template <size_t Depth>
class merkle_path_filler {
private:
    std::deque<fc::uint256> queue;
    static stealth_empty_merkle_roots<Depth> emptyroots;
public:
    merkle_path_filler() : queue() { }
    merkle_path_filler(std::deque<fc::uint256> queue) : queue(queue) { }

    fc::uint256 next(size_t depth) {
        if (queue.size() > 0) {
            fc::uint256 h = queue.front();
            queue.pop_front();

            return h;
        } else {
            return emptyroots.empty_root(depth);
        }
    }

};

template<size_t Depth>
stealth_empty_merkle_roots<Depth> merkle_path_filler<Depth>::emptyroots;


template<size_t Depth>
stealth_empty_merkle_roots<Depth> stealth_incremental_merkle_tree<Depth>::emptyroots;

template<size_t Depth>
stealth_merkle_path stealth_incremental_witness<Depth>::path() const
{
    return tree.path(partial_path());
}

template<size_t Depth>
fc::uint256 stealth_incremental_witness<Depth>::root() const
{
    return tree.root(Depth, partial_path());
}

template<size_t Depth>
void stealth_incremental_witness<Depth>::append(fc::uint256 obj)
{
    if (cursor) {
        cursor->append(obj);

        if (cursor->is_complete(cursor_depth)) {
            filled.push_back(cursor->root(cursor_depth));
            cursor = boost::none;
        }
    } else {
        cursor_depth = tree.next_depth(filled.size());

        if (cursor_depth >= Depth) {
            throw std::runtime_error("tree is full");
        }

        if (cursor_depth == 0) {
            filled.push_back(obj);
        } else {
            cursor = stealth_incremental_merkle_tree<Depth>();
            cursor->append(obj);
        }
    }
}

template<size_t Depth>
std::deque<fc::uint256> stealth_incremental_witness<Depth>::partial_path() const
{
    std::deque<fc::uint256> uncles(filled.begin(), filled.end());

    if (cursor) {
        uncles.push_back(cursor->root(cursor_depth));
    }

    return uncles;
}

template<size_t Depth>
fc::uint256 stealth_incremental_merkle_tree<Depth>::root()
{
    return root(Depth, std::deque<fc::uint256>());
}

template<size_t Depth>
void stealth_incremental_merkle_tree<Depth>::append(fc::uint256 obj)
{
    if (is_complete(Depth)) {
        throw std::runtime_error("tree is full");
    }

    if (!left) {
        // Set the left leaf
        left = obj;
    } else if (!right) {
        // Set the right leaf
        right = obj;
    } else {
        // Combine the leaves and propagate it up the tree
        boost::optional<fc::uint256> combined = combine256(*left, *right);

        // Set the "left" leaf to the object and make the "right" leaf none
        left = obj;
        right = boost::none;

        for (size_t i = 0; i < Depth; i++) {
            if (i < parents.size()) {
                if (parents[i]) {
                    combined = combine256(*parents[i], *combined);
                    parents[i] = boost::none;
                } else {
                    parents[i] = *combined;
                    break;
                }
            } else {
                parents.push_back(combined);
                break;
            }
        }
    }
}

template<size_t Depth>
stealth_incremental_witness<Depth> stealth_incremental_merkle_tree<Depth>::witness() const
{
    return stealth_incremental_witness<Depth>(*this);
}

template<size_t Depth>
fc::uint256 stealth_incremental_merkle_tree<Depth>::empty_root()
{
    return emptyroots.empty_root(Depth);
}

template<size_t Depth>
stealth_merkle_path stealth_incremental_merkle_tree<Depth>::path(
        std::deque<fc::uint256> filler_hashes) const
{
    if (!left) {
        throw std::runtime_error("can't create an authentication path for the beginning of the tree");
    }

    merkle_path_filler<Depth> filler(filler_hashes);

    std::vector<fc::uint256> path;
    std::vector<bool> index;

    if (right) {
        index.push_back(true);
        path.push_back(*left);
    } else {
        index.push_back(false);
        path.push_back(filler.next(0));
    }

    size_t d = 1;

    BOOST_FOREACH(const boost::optional<fc::uint256>& parent, parents) {
        if (parent) {
            index.push_back(true);
            path.push_back(*parent);
        } else {
            index.push_back(false);
            path.push_back(filler.next(d));
        }

        d++;
    }

    while (d < Depth) {
        index.push_back(false);
        path.push_back(filler.next(d));
        d++;
    }

    std::vector<std::vector<bool>> merkle_path;
    BOOST_FOREACH(fc::uint256 b, path)
    {
        std::vector<unsigned char> hashv(b.data(), b.data() + b.data_size());

        merkle_path.push_back(convert_bytes_vector_to_vector(hashv));
    }

    std::reverse(merkle_path.begin(), merkle_path.end());
    std::reverse(index.begin(), index.end());

    return stealth_merkle_path(merkle_path, index);
}

template<size_t Depth>
fc::uint256 stealth_incremental_merkle_tree<Depth>::root(
        size_t depth, std::deque<fc::uint256> filler_hashes) const
{
    merkle_path_filler<Depth> filler(filler_hashes);

    fc::uint256 combine_left =  left  ? *left  : filler.next(0);
    fc::uint256 combine_right = right ? *right : filler.next(0);

    fc::uint256 root = combine256(combine_left, combine_right);

    size_t d = 1;

    BOOST_FOREACH(const boost::optional<fc::uint256>& parent, parents) {
        if (parent) {
            root = combine256(*parent, root);
        } else {
            root = combine256(root, filler.next(d));
        }

        d++;
    }

    // We may not have parents for ancestor trees, so we fill
    // the rest in here.
    while (d < depth) {
        root = combine256(root, filler.next(d));
        d++;
    }

    return root;
}

template<size_t Depth>
bool stealth_incremental_merkle_tree<Depth>::is_complete(size_t depth) const
{
    if (!left || !right) {
        return false;
    }

    if (parents.size() != (depth - 1)) {
        return false;
    }

    BOOST_FOREACH(const boost::optional<fc::uint256>& parent, parents) {
        if (!parent) {
            return false;
        }
    }

    return true;
}

template<size_t Depth>
size_t stealth_incremental_merkle_tree<Depth>::next_depth(size_t skip) const
{
    if (!left) {
        if (skip) {
            skip--;
        } else {
            return 0;
        }
    }

    if (!right) {
        if (skip) {
            skip--;
        } else {
            return 0;
        }
    }

    size_t d = 1;

    BOOST_FOREACH(const boost::optional<fc::uint256>& parent, parents) {
        if (!parent) {
            if (skip) {
                skip--;
            } else {
                return d;
            }
        }

        d++;
    }

    return d + skip;
}

template class stealth_incremental_merkle_tree<29>;
template class stealth_incremental_merkle_tree<4>;
template class stealth_incremental_witness<29>;
template class stealth_incremental_witness<4>;

template<>
stealth_proof::stealth_proof(const r1cs_ppzksnark_proof<curve_pp> &proof)
{
    g_A = CompressedG1(proof.g_A.g);
    g_A_prime = CompressedG1(proof.g_A.h);
    g_B = CompressedG2(proof.g_B.g);
    g_B_prime = CompressedG1(proof.g_B.h);
    g_C = CompressedG1(proof.g_C.g);
    g_C_prime = CompressedG1(proof.g_C.h);
    g_K = CompressedG1(proof.g_K);
    g_H = CompressedG1(proof.g_H);
}

template<>
r1cs_ppzksnark_proof<curve_pp> stealth_proof::to_libsnark_proof() const
{
    r1cs_ppzksnark_proof<curve_pp> proof;

    proof.g_A.g = g_A.to_libsnark_g1<curve_G1>();
    proof.g_A.h = g_A_prime.to_libsnark_g1<curve_G1>();
    proof.g_B.g = g_B.to_libsnark_g2<curve_G2>();
    proof.g_B.h = g_B_prime.to_libsnark_g1<curve_G1>();
    proof.g_C.g = g_C.to_libsnark_g1<curve_G1>();
    proof.g_C.h = g_C_prime.to_libsnark_g1<curve_G1>();
    proof.g_K = g_K.to_libsnark_g1<curve_G1>();
    proof.g_H = g_H.to_libsnark_g1<curve_G1>();

    return proof;
}

stealth_proof stealth_proof::random_invalid()
{
    stealth_proof p;
    p.g_A = curve_G1::random_element();
    p.g_A_prime = curve_G1::random_element();
    p.g_B = curve_G2::random_element();
    p.g_B_prime = curve_G1::random_element();
    p.g_C = curve_G1::random_element();
    p.g_C_prime = curve_G1::random_element();

    p.g_K = curve_G1::random_element();
    p.g_H = curve_G1::random_element();

    return p;
}

template<typename FieldT>
class joinsplit_gadget : gadget<FieldT> {
private:
    // Verifier inputs
    pb_variable_array<FieldT> zk_packed_inputs;
    pb_variable_array<FieldT> zk_unpacked_inputs;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker;

    std::shared_ptr<digest_variable<FieldT>> zk_merkle_root;
    std::shared_ptr<digest_variable<FieldT>> zk_h_sig;
    boost::array<std::shared_ptr<digest_variable<FieldT>>, 2> zk_input_nullifiers;
    boost::array<std::shared_ptr<digest_variable<FieldT>>, 2> zk_input_macs;
    boost::array<std::shared_ptr<digest_variable<FieldT>>, 2> zk_output_commitments;
    pb_variable_array<FieldT> zk_vpub_old;
    pb_variable_array<FieldT> zk_vpub_new;

    // Aux inputs
    pb_variable<FieldT> ZERO;
    std::shared_ptr<digest_variable<FieldT>> zk_phi;
    pb_variable_array<FieldT> zk_total_uint64;

    // Input note gadgets
    boost::array<std::shared_ptr<input_note_gadget<FieldT>>, 2> zk_input_notes;
    boost::array<std::shared_ptr<PRF_pk_gadget<FieldT>>, 2> zk_mac_authentication;

    // Output note gadgets
    boost::array<std::shared_ptr<output_note_gadget<FieldT>>, 2> zk_output_notes;

public:

    joinsplit_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        // Verification
        {
            // The verification inputs are all bit-strings of various
            // lengths (256-bit digests and 64-bit integers) and so we
            // pack them into as few field elements as possible. (The
            // more verification inputs you have, the more expensive
            // verification is.)
            zk_packed_inputs.allocate(pb, verifying_field_element_size());
            pb.set_input_sizes(verifying_field_element_size());

            alloc_uint256(zk_unpacked_inputs, zk_merkle_root);
            alloc_uint256(zk_unpacked_inputs, zk_h_sig);

            for (size_t i = 0; i < 2; i++) {
                alloc_uint256(zk_unpacked_inputs, zk_input_nullifiers[i]);
                alloc_uint256(zk_unpacked_inputs, zk_input_macs[i]);
            }

            for (size_t i = 0; i < 2; i++) {
                alloc_uint256(zk_unpacked_inputs, zk_output_commitments[i]);
            }

            alloc_uint64(zk_unpacked_inputs, zk_vpub_old);
            alloc_uint64(zk_unpacked_inputs, zk_vpub_new);

            assert(zk_unpacked_inputs.size() == verifying_input_bit_size());

            // This gadget will ensure that all of the inputs we provide are
            // boolean constrained.
            unpacker.reset(new multipacking_gadget<FieldT>(
                pb,
                zk_unpacked_inputs,
                zk_packed_inputs,
                FieldT::capacity(),
                "unpacker"
            ));
        }

        // We need a constant "zero" variable in some contexts. In theory
        // it should never be necessary, but libsnark does not synthesize
        // optimal circuits.
        //
        // The first variable of our constraint system is constrained
        // to be one automatically for us, and is known as `ONE`.
        ZERO.allocate(pb);

        zk_phi.reset(new digest_variable<FieldT>(pb, 252, ""));

        zk_total_uint64.allocate(pb, 64);

        for (size_t i = 0; i < 2; i++) {
            // Input note gadget for commitments, macs, nullifiers,
            // and spend authority.
            zk_input_notes[i].reset(new input_note_gadget<FieldT>(
                pb,
                ZERO,
                zk_input_nullifiers[i],
                *zk_merkle_root
            ));

            // The input keys authenticate h_sig to prevent
            // malleability.
            zk_mac_authentication[i].reset(new PRF_pk_gadget<FieldT>(
                pb,
                ZERO,
                zk_input_notes[i]->a_sk->bits,
                zk_h_sig->bits,
                i ? true : false,
                zk_input_macs[i]
            ));
        }

        for (size_t i = 0; i < 2; i++) {
            zk_output_notes[i].reset(new output_note_gadget<FieldT>(
                pb,
                ZERO,
                zk_phi->bits,
                zk_h_sig->bits,
                i ? true : false,
                zk_output_commitments[i]
            ));
        }
    }

    void generate_r1cs_constraints() {
        // The true passed here ensures all the inputs
        // are boolean constrained.
        unpacker->generate_r1cs_constraints(true);

        // Constrain `ZERO`
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

        // Constrain bitness of phi
        zk_phi->generate_r1cs_constraints();

        for (size_t i = 0; i < 2; i++) {
            // Constrain the JoinSplit input constraints.
            zk_input_notes[i]->generate_r1cs_constraints();

            // Authenticate h_sig with a_sk
            zk_mac_authentication[i]->generate_r1cs_constraints();
        }

        for (size_t i = 0; i < 2; i++) {
            // Constrain the JoinSplit output constraints.
            zk_output_notes[i]->generate_r1cs_constraints();
        }

        // Value balance
        {
            linear_combination<FieldT> left_side = packed_addition(zk_vpub_old);
            for (size_t i = 0; i < 2; i++) {
                left_side = left_side + packed_addition(zk_input_notes[i]->value);
            }

            linear_combination<FieldT> right_side = packed_addition(zk_vpub_new);
            for (size_t i = 0; i < 2; i++) {
                right_side = right_side + packed_addition(zk_output_notes[i]->value);
            }

            // Ensure that both sides are equal
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                1,
                left_side,
                right_side
            ));

            // #854: Ensure that left_side is a 64-bit integer.
            for (size_t i = 0; i < 64; i++) {
                generate_boolean_r1cs_constraint<FieldT>(
                    this->pb,
                    zk_total_uint64[i],
                    ""
                );
            }

            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                1,
                left_side,
                packed_addition(zk_total_uint64)
            ));
        }
    }

    void generate_r1cs_witness(
        const uint252& phi,
        const uint256& rt,
        const uint256& h_sig,
        const boost::array<JSInput, 2>& inputs,
        const boost::array<Note, 2>& outputs,
        uint64_t vpub_old,
        uint64_t vpub_new
    ) {
        // Witness `zero`
        this->pb.val(ZERO) = FieldT::zero();

        // Witness rt. This is not a sanity check.
        //
        // This ensures the read gadget constrains
        // the intended root in the event that
        // both inputs are zero-valued.
        zk_merkle_root->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(rt)
        );

        // Witness public balance values
        zk_vpub_old.fill_with_bits(
            this->pb,
            uint64_to_bool_vector(vpub_old)
        );
        zk_vpub_new.fill_with_bits(
            this->pb,
            uint64_to_bool_vector(vpub_new)
        );

        {
            // Witness total_uint64 bits
            uint64_t left_side_acc = vpub_old;
            for (size_t i = 0; i < 2; i++) {
                left_side_acc += inputs[i].note.value;
            }

            zk_total_uint64.fill_with_bits(
                this->pb,
                uint64_to_bool_vector(left_side_acc)
            );
        }

        // Witness phi
        zk_phi->bits.fill_with_bits(
            this->pb,
            uint252_to_bool_vector(phi)
        );

        // Witness h_sig
        zk_h_sig->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(h_sig)
        );

        for (size_t i = 0; i < 2; i++) {
            // Witness the input information.
            auto merkle_path = inputs[i].witness.path();
            zk_input_notes[i]->generate_r1cs_witness(
                merkle_path,
                inputs[i].key,
                inputs[i].note
            );

            // Witness macs
            zk_mac_authentication[i]->generate_r1cs_witness();
        }

        for (size_t i = 0; i < 2; i++) {
            // Witness the output information.
            zk_output_notes[i]->generate_r1cs_witness(outputs[i]);
        }

        // [SANITY CHECK] Ensure that the intended root
        // was witnessed by the inputs, even if the read
        // gadget overwrote it. This allows the prover to
        // fail instead of the verifier, in the event that
        // the roots of the inputs do not match the
        // treestate provided to the proving API.
        zk_merkle_root->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(rt)
        );

        // This happens last, because only by now are all the
        // verifier inputs resolved.
        unpacker->generate_r1cs_witness_from_bits();
    }

    static r1cs_primary_input<FieldT> witness_map(
        const uint256& rt,
        const uint256& h_sig,
        const boost::array<uint256, 2>& macs,
        const boost::array<uint256, 2>& nullifiers,
        const boost::array<uint256, 2>& commitments,
        uint64_t vpub_old,
        uint64_t vpub_new
    ) {
        std::vector<bool> verify_inputs;

        insert_uint256(verify_inputs, rt);
        insert_uint256(verify_inputs, h_sig);

        for (size_t i = 0; i < 2; i++) {
            insert_uint256(verify_inputs, nullifiers[i]);
            insert_uint256(verify_inputs, macs[i]);
        }

        for (size_t i = 0; i < 2; i++) {
            insert_uint256(verify_inputs, commitments[i]);
        }

        insert_uint64(verify_inputs, vpub_old);
        insert_uint64(verify_inputs, vpub_new);

        assert(verify_inputs.size() == verifying_input_bit_size());
        auto verify_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
        assert(verify_field_elements.size() == verifying_field_element_size());
        return verify_field_elements;
    }

    static size_t verifying_input_bit_size() {
        size_t acc = 0;

        acc += 256; // the merkle root (anchor)
        acc += 256; // h_sig
        for (size_t i = 0; i < 2; i++) {
            acc += 256; // nullifier
            acc += 256; // mac
        }
        for (size_t i = 0; i < 2; i++) {
            acc += 256; // new commitment
        }
        acc += 64; // vpub_old
        acc += 64; // vpub_new

        return acc;
    }

    static size_t verifying_field_element_size() {
        return div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    void alloc_uint256(
        pb_variable_array<FieldT>& packed_into,
        std::shared_ptr<digest_variable<FieldT>>& var
    ) {
        var.reset(new digest_variable<FieldT>(this->pb, 256, ""));
        packed_into.insert(packed_into.end(), var->bits.begin(), var->bits.end());
    }

    void alloc_uint64(
        pb_variable_array<FieldT>& packed_into,
        pb_variable_array<FieldT>& integer
    ) {
        integer.allocate(this->pb, 64, "");
        packed_into.insert(packed_into.end(), integer.begin(), integer.end());
    }
};


struct joinsplit_impl : public stealth_joinsplit
{
    typedef default_r1cs_ppzksnark_pp ppzksnark_ppT;
    typedef Fr<ppzksnark_ppT> FieldT;

    boost::optional<r1cs_ppzksnark_proving_key<ppzksnark_ppT>> pk;
    boost::optional<r1cs_ppzksnark_verification_key<ppzksnark_ppT>> vk;
    boost::optional<std::string> pkPath;

    joinsplit_impl() {}
    ~joinsplit_impl() {}

    static void initialize() {
        //TODO: LOCK(cs_InitializeParams);

        ppzksnark_ppT::init_public_params();
    }

    void setProvingKeyPath(std::string path) {
        pkPath = path;
    }

    void loadProvingKey() {
        if (!pk) {
            if (!pkPath) {
                throw std::runtime_error("proving key path unknown");
            }
            loadFromFile(*pkPath, pk);
        }
    }

    void save_proving_key(std::string path) {
        if (pk) {
            save_to_file(path, *pk);
        } else {
            throw std::runtime_error("cannot save proving key; key doesn't exist");
        }
    }

    void load_verifying_key(std::string path) {
        load_from_file(path, vk);
    }

    void save_verifying_key(std::string path) {
        if (vk) {
            save_to_file(path, *vk);
        } else {
            throw std::runtime_error("cannot save verifying key; key doesn't exist");
        }
    }

    void save_r1cs(std::string path) {
        auto r1cs = generate_r1cs();

        save_to_file(path, r1cs);
    }

    r1cs_constraint_system<FieldT> generate_r1cs() {
        protoboard<FieldT> pb;

        joinsplit_gadget<FieldT> g(pb);
        g.generate_r1cs_constraints();

        return pb.get_constraint_system();
    }

    void generate_impl() {
        const r1cs_constraint_system<FieldT> constraint_system = generate_r1cs();
        r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair =
                r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

        pk = keypair.pk;
        vk = keypair.vk;
    }

    bool verify(const stealth_proof &proof,
               const fc::uint256 &public_key_hash,
               const fc::uint256 &random_seed,
               const boost::array<fc::uint256, 2> &hmacs,
               const boost::array<fc::uint256, 2> &nullifiers,
               const boost::array<fc::uint256, 2> &commitments,
               uint64 vpub_old,
               uint64 vpub_new,
               const fc::uint256 &rt)
    {
        if (!vk) {
            throw std::runtime_error("JoinSplit verifying key not loaded");
        }

        try {
            auto r1cs_proof = proof.to_libsnark_proof<r1cs_ppzksnark_proof<ppzksnark_ppT>>();

            fc::uint256 h_sig = this->h_sig(randomSeed, nullifiers, pubKeyHash);

            auto witness = joinsplit_gadget<FieldT>::witness_map(
                rt,
                h_sig,
                macs,
                nullifiers,
                commitments,
                vpub_old,
                vpub_new
            );

            return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(*vk, witness, r1cs_proof);
        } catch (...) {
            return false;
        }
    }

    stealth_proof prove(
            const boost::array<stealth_input, 2> &inputs,
            const boost::array<stealth_output, 2> &outputs,
            boost::array<stealth_note, 2> &out_notes,
            boost::array<binary, 2> &out_ciphertexts,
            fc::ecc::public_key &out_ephemeral_key,
            const fc::uint256 &public_key_hash,
            fc::uint256 &out_random_seed,
            boost::array<fc::uint256, 2> &out_hmacs,
            boost::array<fc::uint256, 2> &out_nullifiers,
            boost::array<fc::uint256, 2> &out_commitments,
            uint64 vpub_old,
            uint64 vpub_new,
            const fc::uint256 &rt,
            bool compute_proof)
    {
        if (compute_proof && !pk) {
            throw std::runtime_error("JoinSplit proving key not loaded");
        }

        if (vpub_old > MAX_MONEY) {
            throw std::invalid_argument("nonsensical vpub_old value");
        }

        if (vpub_new > MAX_MONEY) {
            throw std::invalid_argument("nonsensical vpub_new value");
        }

        uint64 lhs_value = vpub_old;
        uint64 rhs_value = vpub_new;

        for (size_t i = 0; i < 2; i++) {
            // Sanity checks of input
            {
                // If note has nonzero value, its witness's root must be equal to the
                // input.
                if ((inputs[i].note.value != 0) && (inputs[i].witness.root() != rt)) {
                    throw std::invalid_argument("joinsplit not anchored to the correct root");
                }

                // Ensure we have the key to this note.
                if (inputs[i].note.a_pk != inputs[i].key.address().a_pk) {
                    throw std::invalid_argument("input note not authorized to spend with given key");
                }

                // Balance must be sensical
                if (inputs[i].note.value > MAX_MONEY) {
                    throw std::invalid_argument("nonsensical input note value");
                }

                lhs_value += inputs[i].note.value;

                if (lhs_value > MAX_MONEY) {
                    throw std::invalid_argument("nonsensical left hand size of joinsplit balance");
                }
            }

            // Compute nullifier of input
            out_nullifiers[i] = inputs[i].nullifier();
        }

        // Sample randomSeed
        out_randomSeed = random_uint256();

        // Compute h_sig
        uint256 h_sig = this->h_sig(out_randomSeed, out_nullifiers, pubKeyHash);

        // Sample phi
        uint252 phi = random_uint252();

        // Compute notes for outputs
        for (size_t i = 0; i < NumOutputs; i++) {
            // Sanity checks of output
            {
                if (outputs[i].value > MAX_MONEY) {
                    throw std::invalid_argument("nonsensical output value");
                }

                rhs_value += outputs[i].value;

                if (rhs_value > MAX_MONEY) {
                    throw std::invalid_argument("nonsensical right hand side of joinsplit balance");
                }
            }

            // Sample r
            uint256 r = random_uint256();

            out_notes[i] = outputs[i].note(phi, r, i, h_sig);
        }

        if (lhs_value != rhs_value) {
            throw std::invalid_argument("invalid joinsplit balance");
        }

        // Compute the output commitments
        for (size_t i = 0; i < NumOutputs; i++) {
            out_commitments[i] = out_notes[i].cm();
        }

        // Encrypt the ciphertexts containing the note
        // plaintexts to the recipients of the value.
        {
            ZCNoteEncryption encryptor(h_sig);

            for (size_t i = 0; i < NumOutputs; i++) {
                NotePlaintext pt(out_notes[i], outputs[i].memo);

                out_ciphertexts[i] = pt.encrypt(encryptor, outputs[i].addr.pk_enc);
            }

            out_ephemeralKey = encryptor.get_epk();
        }

        // Authenticate h_sig with each of the input
        // spending keys, producing macs which protect
        // against malleability.
        for (size_t i = 0; i < NumInputs; i++) {
            out_macs[i] = PRF_pk(inputs[i].key, i, h_sig);
        }

        if (!computeProof) {
            return ZCProof();
        }

        protoboard<FieldT> pb;
        {
            joinsplit_gadget<FieldT, NumInputs, NumOutputs> g(pb);
            g.generate_r1cs_constraints();
            g.generate_r1cs_witness(
                phi,
                rt,
                h_sig,
                inputs,
                out_notes,
                vpub_old,
                vpub_new
            );
        }

        // The constraint system must be satisfied or there is an unimplemented
        // or incorrect sanity check above. Or the constraint system is broken!
        assert(pb.is_satisfied());

        // TODO: These are copies, which is not strictly necessary.
        std::vector<FieldT> primary_input = pb.primary_input();
        std::vector<FieldT> aux_input = pb.auxiliary_input();

        // Swap A and B if it's beneficial (less arithmetic in G2)
        // In our circuit, we already know that it's beneficial
        // to swap, but it takes so little time to perform this
        // estimate that it doesn't matter if we check every time.
        pb.constraint_system.swap_AB_if_beneficial();

        return ZCProof(r1cs_ppzksnark_prover<ppzksnark_ppT>(
            *pk,
            primary_input,
            aux_input,
            pb.constraint_system
        ));
    }
};


stealth_joinsplit* stealth_joinsplit::generate()
{
    joinsplit_impl::initialize();
    auto js = new joinsplit_impl();
    js->generate_impl();
    return js;
}

stealth_joinsplit* stealth_joinsplit::unopened()
{
    joinsplit_impl::initialize();
    return new joinsplit_impl();
}

fc::uint256 stealth_joinsplit::h_sig(const fc::uint256 &random_seed,
                                const boost::array<fc::uint256, 2> &nullifiers,
                                const fc::uint256 &public_key_hash)
{
    fc::sha256::encoder e;
    fc::raw::pack(e, random_seed);
    fc::raw::pack(e, nullifiers[0]);\
    fc::raw::pack(e, nullifiers[1]);
    fc::raw::pack(e, public_key_hash);
    return e.result();
}


}}

