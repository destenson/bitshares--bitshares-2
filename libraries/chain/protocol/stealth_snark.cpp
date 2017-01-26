#include <graphene/chain/protocol/stealth_snark.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/crypto/dh.hpp>
#include <fc/crypto/aes.hpp>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

namespace graphene { namespace chain {

typedef libsnark::alt_bn128_pp curve_pp;
typedef libsnark::alt_bn128_pp::G1_type curve_G1;
typedef libsnark::alt_bn128_pp::G2_type curve_G2;
typedef libsnark::alt_bn128_pp::GT_type curve_GT;
typedef libsnark::alt_bn128_pp::Fp_type curve_Fr;
typedef libsnark::alt_bn128_pp::Fq_type curve_Fq;
typedef libsnark::alt_bn128_pp::Fqe_type curve_Fq2;

template<>
stealth_proof::stealth_proof(const libsnark::r1cs_ppzksnark_proof<curve_pp> &proof)
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
libsnark::r1cs_ppzksnark_proof<curve_pp> stealth_proof::to_libsnark_proof() const
{
    libsnark::r1cs_ppzksnark_proof<curve_pp> proof;

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

}}
