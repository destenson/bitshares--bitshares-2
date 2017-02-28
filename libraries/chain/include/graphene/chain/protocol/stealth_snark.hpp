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
#include <graphene/chain/protocol/stealth_zk.hpp>
#include <fc/crypto/elliptic.hpp>
#include <boost/array.hpp>
#include <boost/optional.hpp>
#include <boost/foreach.hpp>

#include <gadgetlib1/gadgets/basic_gadgets.hpp>
#include <gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <common/default_types/r1cs_ppzksnark_pp.hpp>
#include <zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

typedef libsnark::alt_bn128_pp curve_pp;
typedef libsnark::alt_bn128_pp::G1_type curve_G1;
typedef libsnark::alt_bn128_pp::G2_type curve_G2;
typedef libsnark::alt_bn128_pp::GT_type curve_GT;
typedef libsnark::alt_bn128_pp::Fp_type curve_Fr;
typedef libsnark::alt_bn128_pp::Fq_type curve_Fq;
typedef libsnark::alt_bn128_pp::Fqe_type curve_Fq2;

namespace graphene { namespace chain {

const unsigned char G1_PREFIX_MASK = 0x02;
const unsigned char G2_PREFIX_MASK = 0x0a;

// Element in the base field
struct Fq
{
    fc::uint256 data;

    Fq(): data() {}

    template<typename libsnark_Fq>
    Fq(libsnark_Fq element);

    template<typename libsnark_Fq>
    libsnark_Fq to_libsnark_fq() const;
};

bool operator ==(const Fq& p1, const Fq&p2);
bool operator !=(const Fq& p1, const Fq&p2);

// Element in the extension field
struct Fq2
{
    fc::uint512 data;

    Fq2(): data() {}

    template<typename libsnark_Fq2>
    Fq2(libsnark_Fq2 element);

    template<typename libsnark_Fq2>
    libsnark_Fq2 to_libsnark_fq2() const;
};

bool operator ==(const Fq2& p1, const Fq2&p2);
bool operator !=(const Fq2& p1, const Fq2&p2);

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

bool operator ==(const CompressedG1& p1, const CompressedG1&p2);
bool operator !=(const CompressedG1& p1, const CompressedG1&p2);

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

bool operator ==(const CompressedG2& p1, const CompressedG2&p2);
bool operator !=(const CompressedG2& p1, const CompressedG2&p2);

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

    stealth_proof() {}
    // Produces a compressed proof using a libsnark zkSNARK proof
    template<typename libsnark_proof>
    stealth_proof(const libsnark_proof& proof);

    // Produces a libsnark zkSNARK proof out of this proof,
    // or throws an exception if it is invalid.
    template<typename libsnark_proof>
    libsnark_proof to_libsnark_proof() const;

    static stealth_proof random_invalid();
};

bool operator ==(const stealth_proof& p1, const stealth_proof&p2);
bool operator !=(const stealth_proof& p1, const stealth_proof&p2);

template<typename T>
T swap_endianness_u64(T v) {
    if (v.size() != 64) {
        throw std::length_error("invalid bit length for 64-bit unsigned integer");
    }

    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 8; j++) {
            std::swap(v[i*8 + j], v[((7-i)*8)+j]);
        }
    }

    return v;
}

template<typename FieldT>
libsnark::linear_combination<FieldT> packed_addition(libsnark::pb_variable_array<FieldT> input) {
    auto input_swapped = swap_endianness_u64(input);

    return libsnark::pb_packing_sum<FieldT>(libsnark::pb_variable_array<FieldT>(
        input_swapped.rbegin(), input_swapped.rend()
    ));
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> from_bits(std::vector<bool> bits,
                                              libsnark::pb_variable<FieldT>& ZERO) {
    libsnark::pb_variable_array<FieldT> acc;

    BOOST_FOREACH(bool bit, bits) {
        acc.emplace_back(bit ? (libsnark::ONE) : ZERO);
    }

    return acc;
}

template<typename FieldT>
class PRF_gadget : libsnark::gadget<FieldT> {
private:
    std::shared_ptr<libsnark::block_variable<FieldT>> block;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> hasher;
    std::shared_ptr<libsnark::digest_variable<FieldT>> result;

public:
    PRF_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        bool a,
        bool b,
        bool c,
        bool d,
        libsnark::pb_variable_array<FieldT> x,
        libsnark::pb_variable_array<FieldT> y,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result
    ) : libsnark::gadget<FieldT>(pb), result(result) {

        libsnark::pb_linear_combination_array<FieldT> IV = libsnark::SHA256_default_IV(pb);

        libsnark::pb_variable_array<FieldT> discriminants;
        discriminants.emplace_back(a ? (libsnark::ONE) : ZERO);
        discriminants.emplace_back(b ? (libsnark::ONE) : ZERO);
        discriminants.emplace_back(c ? (libsnark::ONE) : ZERO);
        discriminants.emplace_back(d ? (libsnark::ONE) : ZERO);

        block.reset(new libsnark::block_variable<FieldT>(pb, {
            discriminants,
            x,
            y
        }, "PRF_block"));

        hasher.reset(new libsnark::sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block->bits,
            *result,
        "PRF_hasher"));
    }

    void generate_r1cs_constraints() {
        hasher->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher->generate_r1cs_witness();
    }
};

template<typename FieldT>
libsnark::pb_variable_array<FieldT> gen256zeroes(libsnark::pb_variable<FieldT>& ZERO) {
    libsnark::pb_variable_array<FieldT> ret;
    while (ret.size() < 256) {
        ret.emplace_back(ZERO);
    }

    return ret;
}

template<typename FieldT>
class PRF_addr_a_pk_gadget : public PRF_gadget<FieldT> {
public:
    PRF_addr_a_pk_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& a_sk,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result
    ) : PRF_gadget<FieldT>(pb, ZERO, 1, 1, 0, 0, a_sk, gen256zeroes(ZERO), result) {}
};

template<typename FieldT>
class PRF_nf_gadget : public PRF_gadget<FieldT> {
public:
    PRF_nf_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& a_sk,
        libsnark::pb_variable_array<FieldT>& rho,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result
    ) : PRF_gadget<FieldT>(pb, ZERO, 1, 1, 1, 0, a_sk, rho, result) {}
};

template<typename FieldT>
class PRF_pk_gadget : public PRF_gadget<FieldT> {
public:
    PRF_pk_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& a_sk,
        libsnark::pb_variable_array<FieldT>& h_sig,
        bool nonce,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result
    ) : PRF_gadget<FieldT>(pb, ZERO, 0, nonce, 0, 0, a_sk, h_sig, result) {}
};

template<typename FieldT>
class PRF_rho_gadget : public PRF_gadget<FieldT> {
public:
    PRF_rho_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& phi,
        libsnark::pb_variable_array<FieldT>& h_sig,
        bool nonce,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result
    ) : PRF_gadget<FieldT>(pb, ZERO, 0, nonce, 1, 0, phi, h_sig, result) {}
};

template<typename FieldT>
class note_commitment_gadget : libsnark::gadget<FieldT> {
private:
    std::shared_ptr<libsnark::block_variable<FieldT>> block1;
    std::shared_ptr<libsnark::block_variable<FieldT>> block2;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<libsnark::digest_variable<FieldT>> intermediate_hash;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> hasher2;

public:
    note_commitment_gadget(
        libsnark::protoboard<FieldT> &pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& a_pk,
        libsnark::pb_variable_array<FieldT>& v,
        libsnark::pb_variable_array<FieldT>& rho,
        libsnark::pb_variable_array<FieldT>& r,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result
    ) : libsnark::gadget<FieldT>(pb) {
        libsnark::pb_variable_array<FieldT> leading_byte =
            from_bits({1, 0, 1, 1, 0, 0, 0, 0}, ZERO);

        libsnark::pb_variable_array<FieldT> first_of_rho(rho.begin(), rho.begin()+184);
        libsnark::pb_variable_array<FieldT> last_of_rho(rho.begin()+184, rho.end());

        intermediate_hash.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));

        // final padding
        libsnark::pb_variable_array<FieldT> length_padding =
            from_bits({
                // padding
                1,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,

                // length of message (840 bits)
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,1,1,
                0,1,0,0,1,0,0,0
            }, ZERO);

        block1.reset(new libsnark::block_variable<FieldT>(pb, {
            leading_byte,
            a_pk,
            v,
            first_of_rho
        }, ""));

        block2.reset(new libsnark::block_variable<FieldT>(pb, {
            last_of_rho,
            r,
            length_padding
        }, ""));

        libsnark::pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new libsnark::sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash,
        ""));

        libsnark::pb_linear_combination_array<FieldT> IV2(intermediate_hash->bits);

        hasher2.reset(new libsnark::sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            block2->bits,
            *result,
        ""));
    }

    void generate_r1cs_constraints() {
        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();
    }
};


template<typename FieldT>
class note_gadget : public libsnark::gadget<FieldT> {
public:
    libsnark::pb_variable_array<FieldT> value;
    std::shared_ptr<libsnark::digest_variable<FieldT>> r;

    note_gadget(libsnark::protoboard<FieldT> &pb) : libsnark::gadget<FieldT>(pb)
    {
        value.allocate(pb, 64);
        r.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
    }

    void generate_r1cs_constraints()
    {
        for (size_t i = 0; i < 64; i++)
        {
            libsnark::generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                value[i],
                "boolean_value"
            );
        }

        r->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const stealth_note& note)
    {
        r->bits.fill_with_bits(this->pb, convert_uint256_to_bool_vector(note.trapdoor));
        value.fill_with_bits(this->pb, convert_int_to_bool_vector(note.amount.amount.value));
    }
};

template<typename FieldT>
class merkle_tree_gadget : libsnark::gadget<FieldT> {
private:
    typedef libsnark::sha256_two_to_one_hash_gadget<FieldT> sha256_gadget;

    libsnark::pb_variable_array<FieldT> positions;
    std::shared_ptr<libsnark::merkle_authentication_path_variable<FieldT, sha256_gadget>> authvars;
    std::shared_ptr<libsnark::merkle_tree_check_read_gadget<FieldT, sha256_gadget>> auth;

public:
    merkle_tree_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::digest_variable<FieldT> leaf,
        libsnark::digest_variable<FieldT> root,
        libsnark::pb_variable<FieldT>& enforce
    ) : libsnark::gadget<FieldT>(pb) {
        positions.allocate(pb, INCREMENTAL_MERKLE_TREE_DEPTH);
        authvars.reset(new libsnark::merkle_authentication_path_variable<FieldT, sha256_gadget>(
            pb, INCREMENTAL_MERKLE_TREE_DEPTH, "auth"
        ));
        auth.reset(new libsnark::merkle_tree_check_read_gadget<FieldT, sha256_gadget>(
            pb,
            INCREMENTAL_MERKLE_TREE_DEPTH,
            positions,
            leaf,
            root,
            *authvars,
            enforce,
            ""
        ));
    }

    void generate_r1cs_constraints() {
        for (size_t i = 0; i < INCREMENTAL_MERKLE_TREE_DEPTH; i++) {
            // TODO: This might not be necessary, and doesn't
            // appear to be done in libsnark's tests, but there
            // is no documentation, so let's do it anyway to
            // be safe.
            libsnark::generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                positions[i],
                "boolean_positions"
            );
        }

        authvars->generate_r1cs_constraints();
        auth->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const stealth_merkle_path& path) {
        // TODO: Change libsnark so that it doesn't require this goofy
        // number thing in its API.
        size_t path_index = convert_bool_vector_to_int(path.index);

        positions.fill_with_bits_of_ulong(this->pb, path_index);

        authvars->generate_r1cs_witness(path_index, path.authentication_path);
        auth->generate_r1cs_witness();
    }
};

template<typename FieldT>
class input_note_gadget : public note_gadget<FieldT> {
private:
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk;
    std::shared_ptr<libsnark::digest_variable<FieldT>> rho;

    std::shared_ptr<libsnark::digest_variable<FieldT>> commitment;
    std::shared_ptr<note_commitment_gadget<FieldT>> commit_to_inputs;

    libsnark::pb_variable<FieldT> value_enforce;
    std::shared_ptr<merkle_tree_gadget<FieldT>> witness_input;

    std::shared_ptr<PRF_addr_a_pk_gadget<FieldT>> spend_authority;
    std::shared_ptr<PRF_nf_gadget<FieldT>> expose_nullifiers;
public:
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk;

    input_note_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier,
        libsnark::digest_variable<FieldT> rt
    ) : note_gadget<FieldT>(pb) {
        a_sk.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        a_pk.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        rho.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        commitment.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));

        spend_authority.reset(new PRF_addr_a_pk_gadget<FieldT>(
            pb,
            ZERO,
            a_sk->bits,
            a_pk
        ));

        expose_nullifiers.reset(new PRF_nf_gadget<FieldT>(
            pb,
            ZERO,
            a_sk->bits,
            rho->bits,
            nullifier
        ));

        commit_to_inputs.reset(new note_commitment_gadget<FieldT>(
            pb,
            ZERO,
            a_pk->bits,
            this->value,
            rho->bits,
            this->r->bits,
            commitment
        ));

        value_enforce.allocate(pb);

        witness_input.reset(new merkle_tree_gadget<FieldT>(
            pb,
            *commitment,
            rt,
            value_enforce
        ));
    }

    void generate_r1cs_constraints()
    {
        note_gadget<FieldT>::generate_r1cs_constraints();

        a_sk->generate_r1cs_constraints();
        rho->generate_r1cs_constraints();

        spend_authority->generate_r1cs_constraints();
        expose_nullifiers->generate_r1cs_constraints();

        commit_to_inputs->generate_r1cs_constraints();

        // value * (1 - enforce) = 0
        // Given `enforce` is boolean constrained:
        // If `value` is zero, `enforce` _can_ be zero.
        // If `value` is nonzero, `enforce` _must_ be one.
        libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, value_enforce,"");

        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
            packed_addition(this->value),
            (1 - value_enforce),
            0
        ), "");

        witness_input->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(
        const stealth_merkle_path& path,
        const stealth_spending_key& key,
        const stealth_note& note
    ) {
        note_gadget<FieldT>::generate_r1cs_witness(note);

        // Witness a_sk for the input
        a_sk->bits.fill_with_bits(
            this->pb,
            convert_uint256_to_bool_vector(key.value.get_secret())
        );

        // [SANITY CHECK] Witness a_pk with note information
        a_pk->bits.fill_with_bits(
            this->pb,
            convert_uint256_to_bool_vector(note.paying_key)
        );

        // Witness a_pk for a_sk with PRF_addr
        spend_authority->generate_r1cs_witness();

        // Witness rho for the input note
        rho->bits.fill_with_bits(
            this->pb,
            convert_uint256_to_bool_vector(note.trapdoor)
        );

        // Witness the nullifier for the input note
        expose_nullifiers->generate_r1cs_witness();

        // [SANITY CHECK] Ensure the commitment is
        // valid.
        commitment->bits.fill_with_bits(
            this->pb,
            convert_uint256_to_bool_vector(note.commitment())
        );

        // Witness the commitment of the input note
        commit_to_inputs->generate_r1cs_witness();

        // Set enforce flag for nonzero input value
        this->pb.val(value_enforce) = (note.amount.amount != 0) ?
                    FieldT::one() : FieldT::zero();

        // Witness merkle tree authentication path
        witness_input->generate_r1cs_witness(path);
    }
};

template<typename FieldT>
class output_note_gadget : public note_gadget<FieldT> {
private:
    std::shared_ptr<libsnark::digest_variable<FieldT>> rho;
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk;

    std::shared_ptr<PRF_rho_gadget<FieldT>> prevent_faerie_gold;
    std::shared_ptr<note_commitment_gadget<FieldT>> commit_to_outputs;

public:
    output_note_gadget(
        libsnark::protoboard<FieldT>& pb,
        libsnark::pb_variable<FieldT>& ZERO,
        libsnark::pb_variable_array<FieldT>& phi,
        libsnark::pb_variable_array<FieldT>& h_sig,
        bool nonce,
        std::shared_ptr<libsnark::digest_variable<FieldT>> commitment
    ) : note_gadget<FieldT>(pb) {
        rho.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        a_pk.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));

        // Do not allow the caller to choose the same "rho"
        // for any two valid notes in a given view of the
        // blockchain. See protocol specification for more
        // details.
        prevent_faerie_gold.reset(new PRF_rho_gadget<FieldT>(
            pb,
            ZERO,
            phi,
            h_sig,
            nonce,
            rho
        ));

        // Commit to the output notes publicly without
        // disclosing them.
        commit_to_outputs.reset(new note_commitment_gadget<FieldT>(
            pb,
            ZERO,
            a_pk->bits,
            this->value,
            rho->bits,
            this->r->bits,
            commitment
        ));
    }

    void generate_r1cs_constraints() {
        note_gadget<FieldT>::generate_r1cs_constraints();

        a_pk->generate_r1cs_constraints();

        prevent_faerie_gold->generate_r1cs_constraints();

        commit_to_outputs->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const stealth_note& note) {
        note_gadget<FieldT>::generate_r1cs_witness(note);

        // [SANITY CHECK] Witness rho ourselves with the
        // note information.
        rho->bits.fill_with_bits(
            this->pb,
            convert_uint256_to_bool_vector(note.nullifier_base)
        );

        prevent_faerie_gold->generate_r1cs_witness();

        a_pk->bits.fill_with_bits(
            this->pb,
            convert_uint256_to_bool_vector(note.paying_key)
        );

        commit_to_outputs->generate_r1cs_witness();
    }
};

template<typename FieldT>
class joinsplit_gadget : libsnark::gadget<FieldT> {
private:
    // Verifier inputs
    libsnark::pb_variable_array<FieldT> zk_packed_inputs;
    libsnark::pb_variable_array<FieldT> zk_unpacked_inputs;
    std::shared_ptr<libsnark::multipacking_gadget<FieldT>> unpacker;

    std::shared_ptr<libsnark::digest_variable<FieldT>> zk_merkle_root;
    std::shared_ptr<libsnark::digest_variable<FieldT>> zk_h_sig;
    boost::array<std::shared_ptr<libsnark::digest_variable<FieldT>>, 2> zk_input_nullifiers;
    boost::array<std::shared_ptr<libsnark::digest_variable<FieldT>>, 2> zk_input_macs;
    boost::array<std::shared_ptr<libsnark::digest_variable<FieldT>>, 2> zk_output_commitments;
    libsnark::pb_variable_array<FieldT> zk_vpub_old;
    libsnark::pb_variable_array<FieldT> zk_vpub_new;

    // Aux inputs
    libsnark::pb_variable<FieldT> ZERO;
    std::shared_ptr<libsnark::digest_variable<FieldT>> zk_phi;
    libsnark::pb_variable_array<FieldT> zk_total_uint64;

    // Input note gadgets
    boost::array<std::shared_ptr<input_note_gadget<FieldT>>, 2> zk_input_notes;
    boost::array<std::shared_ptr<PRF_pk_gadget<FieldT>>, 2> zk_mac_authentication;

    // Output note gadgets
    boost::array<std::shared_ptr<output_note_gadget<FieldT>>, 2> zk_output_notes;

public:

    joinsplit_gadget(libsnark::protoboard<FieldT> &pb) : libsnark::gadget<FieldT>(pb) {
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
            unpacker.reset(new libsnark::multipacking_gadget<FieldT>(
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

        zk_phi.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));

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
        libsnark::generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO,
                                                                FieldT::zero(), "ZERO");

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
            libsnark::linear_combination<FieldT> left_side = packed_addition(zk_vpub_old);
            for (size_t i = 0; i < 2; i++) {
                left_side = left_side + packed_addition(zk_input_notes[i]->value);
            }

            libsnark::linear_combination<FieldT> right_side = packed_addition(zk_vpub_new);
            for (size_t i = 0; i < 2; i++) {
                right_side = right_side + packed_addition(zk_output_notes[i]->value);
            }

            // Ensure that both sides are equal
            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
                1,
                left_side,
                right_side
            ));

            // #854: Ensure that left_side is a 64-bit integer.
            for (size_t i = 0; i < 64; i++) {
                libsnark::generate_boolean_r1cs_constraint<FieldT>(
                    this->pb,
                    zk_total_uint64[i],
                    ""
                );
            }

            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
                1,
                left_side,
                packed_addition(zk_total_uint64)
            ));
        }
    }

    void generate_r1cs_witness(
        const fc::uint256& phi,
        const fc::uint256& rt,
        const fc::uint256& h_sig,
        const boost::array<stealth_input, 2>& inputs,
        const boost::array<stealth_note, 2>& outputs,
        u_int64_t vpub_old,
        u_int64_t vpub_new
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
            convert_uint256_to_bool_vector(rt)
        );

        // Witness public balance values
        zk_vpub_old.fill_with_bits(
            this->pb,
            convert_int_to_bool_vector(vpub_old)
        );
        zk_vpub_new.fill_with_bits(
            this->pb,
            convert_int_to_bool_vector(vpub_new)
        );

        {
            // Witness total_uint64 bits
            u_int64_t left_side_acc = vpub_old;
            for (size_t i = 0; i < 2; i++) {
                left_side_acc += inputs[i].note.amount.amount.value;
            }

            zk_total_uint64.fill_with_bits(
                this->pb,
                convert_int_to_bool_vector(left_side_acc)
            );
        }

        // Witness phi
        zk_phi->bits.fill_with_bits(
            this->pb,
            convert_uint256_to_bool_vector(phi)
        );

        // Witness h_sig
        zk_h_sig->bits.fill_with_bits(
            this->pb,
            convert_uint256_to_bool_vector(h_sig)
        );

        for (size_t i = 0; i < 2; i++) {
            // Witness the input information.
            auto merkle_path = inputs[i].witness.path();
            zk_input_notes[i]->generate_r1cs_witness(
                merkle_path,
                inputs[i].spending_key,
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
            convert_uint256_to_bool_vector(rt)
        );

        // This happens last, because only by now are all the
        // verifier inputs resolved.
        unpacker->generate_r1cs_witness_from_bits();
    }

    static libsnark::r1cs_primary_input<FieldT> witness_map(
        const fc::uint256& rt,
        const fc::uint256& h_sig,
        const boost::array<fc::uint256, 2>& macs,
        const boost::array<fc::uint256, 2>& nullifiers,
        const boost::array<fc::uint256, 2>& commitments,
        u_int64_t vpub_old,
        u_int64_t vpub_new
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
        auto verify_field_elements =
                libsnark::pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
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
        return libsnark::div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    void alloc_uint256(
        libsnark::pb_variable_array<FieldT>& packed_into,
        std::shared_ptr<libsnark::digest_variable<FieldT>>& var
    ) {
        var.reset(new libsnark::digest_variable<FieldT>(this->pb, 256, ""));
        packed_into.insert(packed_into.end(), var->bits.begin(), var->bits.end());
    }

    void alloc_uint64(
        libsnark::pb_variable_array<FieldT>& packed_into,
        libsnark::pb_variable_array<FieldT>& integer
    ) {
        integer.allocate(this->pb, 64, "");
        packed_into.insert(packed_into.end(), integer.begin(), integer.end());
    }
};

struct stealth_joinsplit
{
    static std::unique_ptr<stealth_joinsplit> generate();
    static std::unique_ptr<stealth_joinsplit> unopened();

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
        u_int64_t vpub_old,
        u_int64_t vpub_new,
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
        u_int64_t vpub_old,
        u_int64_t vpub_new,
        const fc::uint256& rt
    ) = 0;

    // key's loading
    virtual void load_proving_key(std::string path) = 0;
    virtual void save_proving_key(std::string path) = 0;
    virtual void load_verifying_key(std::string path) = 0; \
    virtual void save_verifying_key(std::string path) = 0; \
    virtual bool is_equal(const stealth_joinsplit& other) = 0;
};

}}
