#include <graphene/chain/protocol/stealth_snark.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/crypto/dh.hpp>
#include <fc/crypto/aes.hpp>

#include <common/default_types/r1cs_ppzksnark_pp.hpp>
#include <zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>


namespace graphene { namespace chain {

uint64_t static inline ReadBE64(const unsigned char* ptr)
{
    return be64toh(*((uint64_t*)ptr));
}

void static inline WriteBE64(unsigned char* ptr, uint64_t x)
{
    *((uint64_t*)ptr) = htobe64(x);
}

// FE2IP as defined in the protocol spec and IEEE Std 1363a-2004.
libsnark::bigint<8> fq2_to_bigint(const curve_Fq2 &e)
{
    auto modq = curve_Fq::field_char();
    auto c0 = e.c0.as_bigint();
    auto c1 = e.c1.as_bigint();

    libsnark::bigint<8> temp = c1 * modq;
    temp += c0;
    return temp;
}

// Writes a bigint in big endian
template<mp_size_t LIMBS>
void write_bigint(binary &blob,
                  const libsnark::bigint<LIMBS> &val)
{
    if(blob.size() != LIMBS * sizeof(mp_limb_t))
        throw std::runtime_error("Incorrect bigint blob size");
    auto ptr = blob.begin();
    for (ssize_t i = LIMBS-1; i >= 0; i--, ptr += 8) {
        WriteBE64(ptr, val.data[i]);
    }
}

// Writes a bigint in big endian
template<mp_size_t LIMBS>
void write_bigint(fc::uint256 &blob,
                  const libsnark::bigint<LIMBS> &val)
{
    if(blob.data_size() != LIMBS * sizeof(mp_limb_t))
        throw std::runtime_error("Incorrect bigint blob size");
    unsigned char* ptr = reinterpret_cast<unsigned char*>(blob.data());
    for (ssize_t i = LIMBS-1; i >= 0; i--, ptr += 8) {
        WriteBE64(ptr, val.data[i]);
    }
}

// Writes a bigint in big endian
template<mp_size_t LIMBS>
void write_bigint(fc::uint512 &blob,
                  const libsnark::bigint<LIMBS> &val)
{
    if(blob.data_size() != LIMBS * sizeof(mp_limb_t))
        throw std::runtime_error("Incorrect bigint blob size");
    unsigned char* ptr = reinterpret_cast<unsigned char*>(blob.data());
    for (ssize_t i = LIMBS-1; i >= 0; i--, ptr += 8) {
        WriteBE64(ptr, val.data[i]);
    }
}

// Reads a bigint from big endian
template<mp_size_t LIMBS>
libsnark::bigint<LIMBS> read_bigint(const binary &blob)
{
    if(blob.size() != LIMBS * sizeof(mp_limb_t))
        throw std::runtime_error("Incorrect bigint blob size");    libsnark::bigint<LIMBS> ret;

    const char* ptr = blob.data();

    for (ssize_t i = LIMBS-1; i >= 0; i--, ptr += 8) {
        ret.data[i] = ReadBE64(reinterpret_cast<const unsigned char*>(ptr));
    }

    return ret;
}

template<>
Fq::Fq(curve_Fq element) : data()
{
    write_bigint<4>(data, element.as_bigint());
}

template<>
curve_Fq Fq::to_libsnark_fq() const
{
    auto element_bigint = read_bigint<4>(binary(data.data(), data.data() + data.data_size()));

    // Check that the integer is smaller than the modulus
    auto modq = curve_Fq::field_char();
    element_bigint.limit(modq, "element is not in Fq");

    return curve_Fq(element_bigint);
}

template<>
Fq2::Fq2(curve_Fq2 element) : data()
{
    write_bigint<8>(data, fq2_to_bigint(element));
}

template<>
curve_Fq2 Fq2::to_libsnark_fq2() const
{
    libsnark::bigint<4> modq = curve_Fq::field_char();
    libsnark::bigint<8> combined = read_bigint<8>(binary(data.data(), data.data() + data.data_size()));
    libsnark::bigint<5> res;
    libsnark::bigint<4> c0;
    libsnark::bigint<8>::div_qr(res, c0, combined, modq);
    libsnark::bigint<4> c1 = res.shorten(modq, "element is not in Fq2");

    return curve_Fq2(curve_Fq(c0), curve_Fq(c1));
}

template<>
CompressedG1::CompressedG1(curve_G1 point)
{
    if (point.is_zero()) {
        throw std::domain_error("curve point is zero");
    }

    point.to_affine_coordinates();

    x = Fq(point.X);
    y_lsb = point.Y.as_bigint().data[0] & 1;
}

template<>
curve_G1 CompressedG1::to_libsnark_g1() const
{
    curve_Fq x_coordinate = x.to_libsnark_fq<curve_Fq>();

    // y = +/- sqrt(x^3 + b)
    auto y_coordinate = ((x_coordinate.squared() * x_coordinate) + libsnark::alt_bn128_coeff_b).sqrt();

    if ((y_coordinate.as_bigint().data[0] & 1) != y_lsb) {
        y_coordinate = -y_coordinate;
    }

    curve_G1 r = curve_G1::one();
    r.X = x_coordinate;
    r.Y = y_coordinate;
    r.Z = curve_Fq::one();

    assert(r.is_well_formed());

    return r;
}

template<>
CompressedG2::CompressedG2(curve_G2 point)
{
    if (point.is_zero()) {
        throw std::domain_error("curve point is zero");
    }

    point.to_affine_coordinates();

    x = Fq2(point.X);
    y_gt = fq2_to_bigint(point.Y) > fq2_to_bigint(-(point.Y));
}

template<>
curve_G2 CompressedG2::to_libsnark_g2() const
{
    auto x_coordinate = x.to_libsnark_fq2<curve_Fq2>();

    // y = +/- sqrt(x^3 + b)
    auto y_coordinate = ((x_coordinate.squared() * x_coordinate) + libsnark::alt_bn128_twist_coeff_b).sqrt();
    auto y_coordinate_neg = -y_coordinate;

    if ((fq2_to_bigint(y_coordinate) > fq2_to_bigint(y_coordinate_neg)) != y_gt) {
        y_coordinate = y_coordinate_neg;
    }

    curve_G2 r = curve_G2::one();
    r.X = x_coordinate;
    r.Y = y_coordinate;
    r.Z = curve_Fq2::one();

    assert(r.is_well_formed());

    return r;
}


template<>
stealth_proof::stealth_proof(const libsnark::r1cs_ppzksnark_proof<curve_pp> &proof)
{
    std::cout << "g_A..." << std::endl;
    g_A = CompressedG1(proof.g_A.g);
    std::cout << "g_A_prime..." << std::endl;
    g_A_prime = CompressedG1(proof.g_A.h);
    std::cout << "g_B..." << std::endl;
    g_B = CompressedG2(proof.g_B.g);
    std::cout << "g_B_prime..." << std::endl;
    g_B_prime = CompressedG1(proof.g_B.h);
    std::cout << "g_C..." << std::endl;
    g_C = CompressedG1(proof.g_C.g);
    std::cout << "g_C_prime..." << std::endl;
    g_C_prime = CompressedG1(proof.g_C.h);
    std::cout << "g_K..." << std::endl;
    g_K = CompressedG1(proof.g_K);
    std::cout << "g_H..." << std::endl;
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

bool operator ==(const stealth_proof &p1, const stealth_proof &p2)
{
    return (
        p1.g_A == p2.g_A &&
        p1.g_A_prime == p2.g_A_prime &&
        p1.g_B == p2.g_B &&
        p1.g_B_prime == p2.g_B_prime &&
        p1.g_C == p2.g_C &&
        p1.g_C_prime == p2.g_C_prime &&
        p1.g_K == p2.g_K &&
        p1.g_H == p2.g_H
    );
}

bool operator !=(const stealth_proof &p1, const stealth_proof &p2)
{
    return !(p1 == p2);
}

bool operator ==(const CompressedG2 &p1, const CompressedG2 &p2)
{
    return (
        p1.y_gt == p2.y_gt &&
        p1.x == p2.x
    );
}

bool operator !=(const CompressedG2 &p1, const CompressedG2 &p2)
{
    return !(p1 == p2);
}

bool operator ==(const CompressedG1 &p1, const CompressedG1 &p2)
{
    return (
        p1.y_lsb == p2.y_lsb &&
        p1.x == p2.x
                );
}

bool operator !=(const CompressedG1 &p1, const CompressedG1 &p2)
{
    return !(p1 == p2);
}

bool operator ==(const Fq2 &p1, const Fq2 &p2)
{
    return p1.data == p2.data;
}

bool operator !=(const Fq2 &p1, const Fq2 &p2)
{
    return !(p1 == p2);
}

bool operator ==(const Fq &p1, const Fq &p2)
{
    return p1.data == p2.data;
}

bool operator !=(const Fq &p1, const Fq &p2)
{
    return !(p1 == p2);
}

}}
