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
#include <graphene/chain/protocol/stealth_snark.hpp>
#include <graphene/chain/database.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/crypto/dh.hpp>
#include <fc/crypto/aes.hpp>

#include <array>
#include <boost/foreach.hpp>

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

std::vector<unsigned char> convert_int_to_bytes_vector(const u_int64_t &val_int)
{
    std::vector<unsigned char> bytes;

    for(size_t i = 0; i < 8; i++) {
        bytes.push_back(val_int >> (i * 8));
    }

    return bytes;
}

// Convert bytes into boolean vector. (MSB to LSB)
std::vector<bool> convert_bytes_vector_to_bool_vector(const std::vector<unsigned char>& bytes) {
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

// Convert boolean vector (big endian) to integer
u_int64_t convert_bool_vector_to_int(const std::vector<bool>& v)
{
    if (v.size() > 64) {
        throw std::length_error ("boolean vector can't be larger than 64 bits");
    }

    u_int64_t result = 0;
    for (size_t i=0; i<v.size();i++) {
        if (v.at(i)) {
            result |= (u_int64_t)1 << ((v.size() - 1) - i);
        }
    }

    return result;
}

std::vector<bool> convert_int_to_bool_vector(const u_int64_t& val_int)
{
    return convert_bytes_vector_to_bool_vector(convert_int_to_bytes_vector(val_int));
}

std::vector<bool> convert_uint256_to_bool_vector(const fc::uint256& val)
{
    std::vector<unsigned char> data(val.data(), val.data() + val.data_size());
    return convert_bytes_vector_to_bool_vector(data);
}

void insert_uint256(std::vector<bool>& into, fc::uint256 from)
{
    std::vector<bool> blob = convert_uint256_to_bool_vector(from);
    into.insert(into.end(), blob.begin(), blob.end());
}

void insert_uint64(std::vector<bool>& into, u_int64_t from)
{
    std::vector<bool> num = convert_int_to_bool_vector(from);
    into.insert(into.end(), num.begin(), num.end());
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

        merkle_path.push_back(convert_bytes_vector_to_bool_vector(hashv));
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


template<typename T>
void save_to_file(std::string path, T& obj) {

    std::stringstream ss;
    ss << obj;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename T>
void load_from_file(std::string path, boost::optional<T>& objIn) {

    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    if(!fh.is_open()) {
        throw std::runtime_error("could not load param file at %s");
    }

    ss << fh.rdbuf();
    fh.close();

    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    T obj;
    ss >> obj;

    objIn = std::move(obj);
}


struct joinsplit_impl : public stealth_joinsplit
{
    typedef libsnark::default_r1cs_ppzksnark_pp ppzksnark_ppT;
    typedef libsnark::Fr<ppzksnark_ppT> FieldT;

    boost::optional<libsnark::r1cs_ppzksnark_proving_key<ppzksnark_ppT>> pk;
    boost::optional<libsnark::r1cs_ppzksnark_verification_key<ppzksnark_ppT>> vk;
    boost::optional<std::string> pkPath;

    joinsplit_impl() {}
    ~joinsplit_impl() {}

    static void initialize() {
        //TODO: LOCK(cs_InitializeParams);

        ppzksnark_ppT::init_public_params();
    }

    void set_proving_key_path(std::string path) {
        pkPath = path;
    }

    void load_proving_key() {
        if (!pk) {
            if (!pkPath) {
                throw std::runtime_error("proving key path unknown");
            }
            load_from_file(*pkPath, pk);
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

    libsnark::r1cs_constraint_system<FieldT> generate_r1cs() {
        libsnark::protoboard<FieldT> pb;

        joinsplit_gadget<FieldT> g(pb);
        g.generate_r1cs_constraints();

        return pb.get_constraint_system();
    }

    void generate_impl() {
        const libsnark::r1cs_constraint_system<FieldT> constraint_system = generate_r1cs();
        libsnark::r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair =
                libsnark::r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

        pk = keypair.pk;
        vk = keypair.vk;
    }

    bool verify(const stealth_proof &proof,
               const fc::uint256 &public_key_hash,
               const fc::uint256 &random_seed,
               const boost::array<fc::uint256, 2> &hmacs,
               const boost::array<fc::uint256, 2> &nullifiers,
               const boost::array<fc::uint256, 2> &commitments,
               u_int64_t vpub_old,
               u_int64_t vpub_new,
               const fc::uint256 &rt)
    {
        if (!vk) {
            throw std::runtime_error("JoinSplit verifying key not loaded");
        }

        try {
            auto r1cs_proof =
                    proof.to_libsnark_proof<libsnark::r1cs_ppzksnark_proof<ppzksnark_ppT>>();

            fc::uint256 h_sig = this->h_sig(random_seed, nullifiers, public_key_hash);

            auto witness = joinsplit_gadget<FieldT>::witness_map(
                rt,
                h_sig,
                hmacs,
                nullifiers,
                commitments,
                vpub_old,
                vpub_new
            );

            return libsnark::r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(*vk, witness, r1cs_proof);
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
            u_int64_t vpub_old,
            u_int64_t vpub_new,
            const fc::uint256 &rt,
            bool compute_proof)
    {
        if (compute_proof && !pk) {
            throw std::runtime_error("JoinSplit proving key not loaded");
        }

        u_int64_t lhs_value = vpub_old;
        u_int64_t rhs_value = vpub_new;

        for (size_t i = 0; i < 2; i++) {
            // Sanity checks of input
            {
                // If note has nonzero value, its witness's root must be equal to the
                // input.
                if ((inputs[i].note.amount.amount != 0) && (inputs[i].witness.root() != rt)) {
                    throw std::invalid_argument("joinsplit not anchored to the correct root");
                }

                // Ensure we have the key to this note.
                if (inputs[i].note.paying_key != inputs[i].spending_key.address().paying_key) {
                    throw std::invalid_argument("input note not authorized to spend with given key");
                }

                lhs_value += inputs[i].note.amount.amount.value;

            }

            // Compute nullifier of input
            out_nullifiers[i] = inputs[i].nullifier();
        }

        // Sample randomSeed
        out_random_seed = random_uint256();

        // Compute h_sig
        fc::uint256 h_sig = this->h_sig(out_random_seed, out_nullifiers, public_key_hash);

        // Sample phi
        fc::uint256 phi = random_uint256();

        // Compute notes for outputs
        for (size_t i = 0; i < 2; i++)
        {
            rhs_value += outputs[i].value.amount.value;

            // Sample r
            fc::uint256 r = random_uint256();

            out_notes[i] = outputs[i].note(phi, r, i, h_sig);
        }

        if (lhs_value != rhs_value) {
            throw std::invalid_argument("invalid joinsplit balance");
        }

        // Compute the output commitments
        for (size_t i = 0; i < 2; i++) {
            out_commitments[i] = out_notes[i].commitment();
        }

        // Encrypt the ciphertexts containing the note
        // plaintexts to the recipients of the value.
        {
            stealth_note_encryption encryptor(h_sig);

            for (size_t i = 0; i < 2; i++) {
                stealth_note_plaintext pt(out_notes[i], outputs[i].memo);

                out_ciphertexts[i] = pt.encrypt(encryptor, outputs[i].address.transmission_key);
            }

            out_ephemeral_key = encryptor.ephemeral_public_key;
        }

        // Authenticate h_sig with each of the input
        // spending keys, producing macs which protect
        // against malleability.
        for (size_t i = 0; i < 2; i++) {
            out_hmacs[i] = PRF_pk(inputs[i].spending_key.value, i, h_sig);
        }

        if (!compute_proof) {
            return stealth_proof();
        }

        libsnark::protoboard<FieldT> pb;
        {
            joinsplit_gadget<FieldT> g(pb);
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

        return stealth_proof(libsnark::r1cs_ppzksnark_prover<ppzksnark_ppT>(
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

