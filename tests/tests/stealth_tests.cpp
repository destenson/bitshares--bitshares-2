/*
 * Copyright (c) 2015 Cryptonomex, Inc., and contributors.
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

#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>

#include <graphene/chain/database.hpp>
#include <graphene/chain/protocol/protocol.hpp>
#include <graphene/chain/exceptions.hpp>

#include <graphene/chain/protocol/stealth_zk.hpp>
#include <graphene/chain/protocol/stealth_snark.hpp>
#include <fc/crypto/sha256.hpp>
#include <iostream>

using namespace graphene::chain;


BOOST_AUTO_TEST_CASE( stealth_encryption_test )
{ try {
        fc::ecc::private_key sk1 = fc::ecc::private_key::generate();
        stealth_spending_key paying_key({sk1});
        fc::ecc::private_key sk_enc =
                stealth_note_encryption::generate_secret_key(paying_key);
        fc::ecc::public_key pk_enc =
                stealth_note_encryption::generate_public_key(sk_enc);

        fc::uint256 h_sig = random_uint256();
        stealth_note_encryption b = stealth_note_encryption(h_sig);
        for (size_t i = 0; i < 100; i++)
        {
            stealth_note_encryption c = stealth_note_encryption(h_sig);
    
            BOOST_REQUIRE(b.ephemeral_public_key != c.ephemeral_public_key);
        }
    
        binary message;
        for (unsigned char i = 0; i < 32; i++) {
            // Fill the message with dummy data
            message.push_back(i);
        }
    
        for (int i = 0; i < 255; i++) {
            auto ciphertext = b.encrypt(pk_enc, message);
    
            {
                stealth_note_decryption decrypter(sk_enc);
    
                // Test decryption
                auto plaintext = decrypter.decrypt(ciphertext, b.ephemeral_public_key,
                                                   h_sig, i);
                BOOST_REQUIRE(plaintext == message);
    
                // Test wrong nonce
                BOOST_REQUIRE_THROW(decrypter.decrypt(ciphertext, b.ephemeral_public_key,
                                                h_sig, (i == 0) ? 1 : (i - 1)),
                              std::runtime_error);
            
                // Test wrong ephemeral key
                {
                    stealth_note_encryption c = stealth_note_encryption(h_sig);
    
                    BOOST_REQUIRE_THROW(decrypter.decrypt(ciphertext,
                                                          c.ephemeral_public_key,
                                                   h_sig, i), std::runtime_error);
                }
            
                // Test wrong seed
                BOOST_REQUIRE_THROW(decrypter.decrypt(ciphertext, b.ephemeral_public_key,
                                                      random_uint256(), i),
                                    std::runtime_error);
            
                // Test corrupted ciphertext
                ciphertext[10] ^= 0xff;
                BOOST_REQUIRE_THROW(decrypter.decrypt(ciphertext, b.ephemeral_public_key,
                                                      h_sig, i),
                                    std::runtime_error);
                ciphertext[10] ^= 0xff;
            }
    
            {
                // Test wrong private key
                stealth_spending_key paying_key2({fc::ecc::private_key::generate()});
                fc::ecc::private_key sk_enc_2 = stealth_note_encryption::generate_secret_key(paying_key2);
                stealth_note_decryption decrypter(sk_enc_2);
    
                BOOST_REQUIRE_THROW(decrypter.decrypt(ciphertext, b.ephemeral_public_key,
                                                      h_sig, i),
                                    std::runtime_error);
            }
    
        }


} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( stealth_note_test )
{ try {
    stealth_spending_key a_sk({fc::ecc::private_key::generate()});
    fc::ecc::private_key sk_enc =
            stealth_note_encryption::generate_secret_key(a_sk);
    fc::ecc::public_key pk_enc =
            stealth_note_encryption::generate_public_key(sk_enc);

    fc::uint256 h_sig = random_uint256();
    stealth_payment_address addr_pk = a_sk.address();

    stealth_note_encryption encryptor(h_sig);
    fc::ecc::public_key epk = encryptor.ephemeral_public_key;

    stealth_note note(addr_pk.paying_key,
              asset(1945813),
              random_uint256(),
              random_uint256()
             );

    binary memo(STEALTH_MEMO_SIZE, 1);

    stealth_note_plaintext note_pt(note, memo);

    binary ct = note_pt.encrypt(encryptor, pk_enc);

    stealth_note_decryption decryptor(sk_enc);

    auto decrypted = stealth_note_plaintext::decrypt(decryptor, ct, epk, h_sig, 0);
    auto decrypted_note = decrypted.note(addr_pk);

    BOOST_REQUIRE(decrypted_note.paying_key == note.paying_key);
    BOOST_REQUIRE(decrypted_note.nullifier_base == note.nullifier_base);
    BOOST_REQUIRE(decrypted_note.trapdoor == note.trapdoor);
    BOOST_REQUIRE(decrypted_note.amount == note.amount);

    BOOST_REQUIRE(decrypted.memo == note_pt.memo);
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE(stealth_merkle_tree_test)
{ try {
    for (int start = 0; start < 20; start++) {
        merkle_tree new_tree;

        BOOST_REQUIRE(new_tree.root() == merkle_tree::empty_root());

        for (int i = start; i > 0; i--) {
            new_tree.append(fc::uint256("54d626e08c1c802b305dad30b7e54a82f102390cc92c7d4db112048935236e9c"));
        }

        fc::uint256 oldroot = new_tree.root();

        // At this point, appending tons of null objects to the tree
        // should preserve its root.

        for (int i = 0; i < 100; i++) {
            new_tree.append(fc::uint256());
        }

        BOOST_REQUIRE(new_tree.root() == oldroot);
    }
} FC_LOG_AND_RETHROW() }


BOOST_AUTO_TEST_CASE(stealth_proof_test)
{ try {
        libsnark::init_alt_bn128_params();
        std::cout << "Create random proof..." << std::endl;
        stealth_proof p1 = stealth_proof::random_invalid();
        std::cout << "Convert to libsnark form..." << std::endl;
        libsnark::r1cs_ppzksnark_proof<curve_pp> lsp1 =
                p1.to_libsnark_proof<libsnark::r1cs_ppzksnark_proof<curve_pp> >();
        std::cout << "Create proof from libsnark form..." << std::endl;
        stealth_proof p2(lsp1);
        std::cout << "Compare 2 proofs..." << std::endl;
        BOOST_REQUIRE(p1 == p2);
} FC_LOG_AND_RETHROW() }

typedef libsnark::default_r1cs_ppzksnark_pp ppzksnark_ppT;
typedef libsnark::Fr<ppzksnark_ppT> FieldT;

BOOST_AUTO_TEST_CASE( stealth_keys_generation )
{ try {\
    if(!boost::filesystem::exists("proving.key") ||
       !boost::filesystem::exists("verifying.key"))
    {
        libsnark::init_alt_bn128_params();
        std::cout << "Generate joinsplit..." << std::endl;
        std::unique_ptr<stealth_joinsplit> js = stealth_joinsplit::generate();
        std::cout << "Save generated keys..." << std::endl;
        js->save_proving_key("proving.key");
        js->save_verifying_key("verifying.key");

        std::cout << "Create joinsplit..." << std::endl;
        std::unique_ptr<stealth_joinsplit> js2 = stealth_joinsplit::unopened();
        std::cout << "Load generated keys..." << std::endl;
        js2->load_proving_key("proving.key");
        js2->load_verifying_key("verifying.key");
        BOOST_REQUIRE(js->is_equal(*js2.get()));
    }
} FC_LOG_AND_RETHROW() }


struct keys_fixture
{
    keys_fixture()\
    {
        std::ifstream fpk("proving.key", std::ios::binary);
        if(!fpk.is_open())
            throw std::runtime_error("could not load proving key file");
        fpk >> pk;
        std::ifstream fvk("verifying.key", std::ios::binary);
        if(!fvk.is_open())
            throw std::runtime_error("could not load proving key file");
        fvk >> vk;
    }
    ~keys_fixture()
    {
    }

    libsnark::r1cs_ppzksnark_proving_key<ppzksnark_ppT> pk;
    libsnark::r1cs_ppzksnark_verification_key<ppzksnark_ppT> vk;
};

BOOST_FIXTURE_TEST_CASE(stealth_gadgets_test, keys_fixture)
{ try {
        libsnark::init_alt_bn128_params();
        libsnark::default_r1cs_ppzksnark_pp::init_public_params();
        stealth_spending_key recipient_key = stealth_spending_key::random();
        stealth_payment_address recipient_addr = recipient_key.address();
        fc::uint256 phi = random_uint256();
        merkle_tree tree;
        fc::uint256 rt = tree.root();
        fc::uint256 random_seed = random_uint256();
        fc::uint256 public_key_hash = random_uint256();
        boost::array<stealth_input, 2> inputs = {
            stealth_input(), // dummy input
            stealth_input() // dummy input
        };
        boost::array<fc::uint256, 2> nullifiers = {
            inputs[0].nullifier(),
            inputs[1].nullifier()
        };
        fc::uint256 h_sig = stealth_joinsplit::h_sig(random_seed, nullifiers,
                                                     public_key_hash);
        boost::array<stealth_output, 2> outputs = {
            stealth_output(recipient_addr, asset(10)),
            stealth_output() // dummy output
        };
        boost::array<stealth_note, 2> notes;
        for (size_t i = 0; i < 2; i++)
        {
            fc::uint256 r = random_uint256();
            notes[i] = outputs[i].note(phi, r, i, h_sig);
        }
        uint64_t vpub_old = 10;
        uint64_t vpub_new = 0;


        {
            libsnark::protoboard<FieldT> pb;
            size_t num_constraints = 999;
            size_t num_inputs = 100;
            libsnark::pb_variable_array<FieldT> A;
            libsnark::pb_variable_array<FieldT> B;
            libsnark::pb_variable<FieldT> res;

            res.allocate(pb, "res");
            A.allocate(pb, num_constraints, "A");
            B.allocate(pb, num_constraints, "B");

            libsnark::inner_product_gadget<FieldT> compute_inner_product(pb, A, B,
                                                    res, "compute_inner_product");
            compute_inner_product.generate_r1cs_constraints();

            for(size_t i = 0; i < num_constraints; ++i)
            {
                pb.val(A[i]) = FieldT::random_element();
                pb.val(B[i]) = FieldT::random_element();
            }

            compute_inner_product.generate_r1cs_witness();

            pb.set_input_sizes(num_inputs);

            BOOST_REQUIRE(pb.is_satisfied());

            //generator
            std::cout << "generate keypair..." << std::endl;
            auto keypair = libsnark::r1cs_ppzksnark_generator<ppzksnark_ppT>(pb.constraint_system);
            std::cout << "after generate keypair..." << std::endl;

            std::vector<FieldT> primary_input = pb.primary_input();
            std::vector<FieldT> aux_input = pb.auxiliary_input();
            pb.constraint_system.swap_AB_if_beneficial();
            auto r1cs_proof = libsnark::r1cs_ppzksnark_prover<ppzksnark_ppT>(
                        keypair.pk,
                        primary_input,
                        aux_input,
                        pb.constraint_system
                    );
            BOOST_REQUIRE(
                        libsnark::r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(
                            keypair.vk, primary_input, r1cs_proof)
                        );
        }

        {
            libsnark::protoboard<FieldT> pb;
            libsnark::pb_variable<FieldT> ZERO;
            ZERO.allocate(pb);
            libsnark::digest_variable<FieldT> a_sk(pb,  256, "");
            std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk(
                        new libsnark::digest_variable<FieldT>(pb,  256, "")
                            );
            PRF_addr_a_pk_gadget<FieldT> g(pb, ZERO, a_sk.bits, a_pk);
            a_sk.generate_r1cs_constraints();
            g.generate_r1cs_constraints();
            a_sk.bits.fill_with_bits(
                pb,
                convert_uint256_to_bool_vector(recipient_key.value.get_secret())
            );
            g.generate_r1cs_witness();
            BOOST_REQUIRE(pb.is_satisfied());

            //generator
            std::cout << "generate keypair..." << std::endl;
            auto keypair = libsnark::r1cs_ppzksnark_generator<ppzksnark_ppT>(pb.constraint_system);
            std::cout << "after generate keypair..." << std::endl;

            std::vector<FieldT> primary_input = pb.primary_input();
            std::vector<FieldT> aux_input = pb.auxiliary_input();
            pb.constraint_system.swap_AB_if_beneficial();
            auto r1cs_proof = libsnark::r1cs_ppzksnark_prover<ppzksnark_ppT>(
                        keypair.pk,
                        primary_input,
                        aux_input,
                        pb.constraint_system
                    );
            BOOST_REQUIRE(
                        libsnark::r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(
                            keypair.vk, primary_input, r1cs_proof)
                        );
        }

        {
            libsnark::protoboard<FieldT> pb;
            libsnark::pb_variable<FieldT> ZERO;
            ZERO.allocate(pb);
            {
                libsnark::digest_variable<FieldT> a_sk(pb,  256, "");
                libsnark::digest_variable<FieldT> rho(pb,  256, "");
                std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier(
                            new libsnark::digest_variable<FieldT>(pb,  256, "")
                                );
                PRF_nf_gadget<FieldT> g(pb, ZERO, a_sk.bits, rho.bits, nullifier);
                a_sk.generate_r1cs_constraints();
                rho.generate_r1cs_constraints();
                g.generate_r1cs_constraints();
                a_sk.bits.fill_with_bits(
                    pb,
                    convert_uint256_to_bool_vector(recipient_key.value.get_secret())
                );
                rho.bits.fill_with_bits(
                    pb,
                    convert_uint256_to_bool_vector(notes[0].trapdoor)
                );
                g.generate_r1cs_witness();
            }
            BOOST_REQUIRE(pb.is_satisfied());
        }
        {
            libsnark::protoboard<FieldT> pb;
            libsnark::pb_variable<FieldT> ZERO;
            ZERO.allocate(pb);
            {
                libsnark::digest_variable<FieldT> a_sk(pb,  256, "");
                libsnark::digest_variable<FieldT> h_sig_bits(pb,  256, "");
                std::shared_ptr<libsnark::digest_variable<FieldT>> result(
                            new libsnark::digest_variable<FieldT>(pb,  256, "")
                                );
                PRF_pk_gadget<FieldT> g(pb, ZERO, a_sk.bits, h_sig_bits.bits, false, result);
                a_sk.generate_r1cs_constraints();
                h_sig_bits.generate_r1cs_constraints();
                g.generate_r1cs_constraints();
                a_sk.bits.fill_with_bits(
                    pb,
                    convert_uint256_to_bool_vector(recipient_key.value.get_secret())
                );
                h_sig_bits.bits.fill_with_bits(
                    pb,
                    convert_uint256_to_bool_vector(h_sig)
                );
                g.generate_r1cs_witness();
            }
            BOOST_REQUIRE(pb.is_satisfied());
        }
        {
            libsnark::protoboard<FieldT> pb;
            libsnark::pb_variable<FieldT> ZERO;
            ZERO.allocate(pb);
            {
                libsnark::digest_variable<FieldT> phi_bits(pb,  256, "");
                libsnark::digest_variable<FieldT> h_sig_bits(pb,  256, "");
                std::shared_ptr<libsnark::digest_variable<FieldT>> result(
                            new libsnark::digest_variable<FieldT>(pb,  256, "")
                                );
                PRF_rho_gadget<FieldT> g(pb, ZERO, phi_bits.bits, h_sig_bits.bits, false, result);
                phi_bits.generate_r1cs_constraints();
                h_sig_bits.generate_r1cs_constraints();
                g.generate_r1cs_constraints();
                phi_bits.bits.fill_with_bits(
                    pb,
                    convert_uint256_to_bool_vector(phi)
                );
                h_sig_bits.bits.fill_with_bits(
                    pb,
                    convert_uint256_to_bool_vector(h_sig)
                );
                g.generate_r1cs_witness();
            }
            BOOST_REQUIRE(pb.is_satisfied());
        }
        {
            libsnark::protoboard<FieldT> pb;
            libsnark::pb_variable<FieldT> ZERO;
            ZERO.allocate(pb);
            {
                libsnark::digest_variable<FieldT> a_pk(pb,  256, "");
                libsnark::pb_variable_array<FieldT> value;
                value.allocate(pb, 64);
                libsnark::digest_variable<FieldT> rho_bits(pb,  256, "");
                libsnark::digest_variable<FieldT> r(pb,  256, "");
                std::shared_ptr<libsnark::digest_variable<FieldT>> result(
                            new libsnark::digest_variable<FieldT>(pb,  256, "")
                                );
                note_commitment_gadget<FieldT> g(
                            pb, ZERO, a_pk.bits, value, rho_bits.bits, r.bits, result
                            );

                for (size_t i = 0; i < 64; i++) {
                    libsnark::generate_boolean_r1cs_constraint<FieldT>(
                        pb,
                        value[i],
                        "boolean_value"
                    );
                }

                r.generate_r1cs_constraints();

                g.generate_r1cs_constraints();

                g.generate_r1cs_witness();
            }
            BOOST_REQUIRE(pb.is_satisfied());
        }
        {
            libsnark::protoboard<FieldT> pb;
            {
                note_gadget<FieldT> g(pb);
                g.generate_r1cs_constraints();
                g.generate_r1cs_witness(notes[0]);
            }
            BOOST_REQUIRE(pb.is_satisfied());
        }
        {
            libsnark::protoboard<FieldT> pb;
            libsnark::pb_variable<FieldT> ZERO;
            ZERO.allocate(pb);
            {
                libsnark::digest_variable<FieldT> commitment(pb,  256, "");
                libsnark::pb_variable_array<FieldT> value;
                value.allocate(pb, 64);
                libsnark::pb_variable<FieldT> value_enforced;
                value_enforced.allocate(pb);
                libsnark::digest_variable<FieldT> rt(pb,  256, "");
                merkle_tree_gadget<FieldT> g(
                            pb, commitment, rt, value_enforced
                            );

                for (size_t i = 0; i < 64; i++) {
                    libsnark::generate_boolean_r1cs_constraint<FieldT>(
                        pb,
                        value[i],
                        "boolean_value"
                    );
                }
                libsnark::generate_boolean_r1cs_constraint<FieldT>(pb, value_enforced,"");
                pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
                            packed_addition(value),
                            (1 - value_enforced),
                            0
                        ), "");

                g.generate_r1cs_constraints();

                auto merkle_path = inputs[0].witness.path();
                g.generate_r1cs_witness(merkle_path);
            }
            BOOST_REQUIRE(pb.is_satisfied());
        }
        {
            libsnark::protoboard<FieldT> pb;
            libsnark::pb_variable<FieldT> ZERO;
            ZERO.allocate(pb);
            {
                std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier(
                            new libsnark::digest_variable<FieldT>(pb,  256, "")
                                );
                libsnark::digest_variable<FieldT> rt(pb,  256, "");
                input_note_gadget<FieldT> g(
                            pb, ZERO, nullifier, rt
                            );
                rt.generate_r1cs_constraints();
                auto merkle_path = inputs[0].witness.path();
                auto rt_val = inputs[0].witness.root();
                rt.bits.fill_with_bits(pb, convert_uint256_to_bool_vector(rt_val));
                g.generate_r1cs_constraints();
                g.generate_r1cs_witness(merkle_path, recipient_key, notes[0]);
            }
            BOOST_REQUIRE(pb.is_satisfied());
        }
        {
            libsnark::protoboard<FieldT> pb;
            libsnark::pb_variable<FieldT> ZERO;
            ZERO.allocate(pb);
            {
                libsnark::digest_variable<FieldT> phi_bits(pb,  256, "");
                libsnark::digest_variable<FieldT> h_sig_bits(pb,  256, "");
                std::shared_ptr<libsnark::digest_variable<FieldT>> result(
                            new libsnark::digest_variable<FieldT>(pb,  256, "")
                                );
                output_note_gadget<FieldT> g(
                            pb, ZERO, phi_bits.bits, h_sig_bits.bits, false, result
                            );
                phi_bits.generate_r1cs_constraints();
                h_sig_bits.generate_r1cs_constraints();
                g.generate_r1cs_constraints();
                phi_bits.bits.fill_with_bits(
                    pb,
                    convert_uint256_to_bool_vector(phi)
                );
                h_sig_bits.bits.fill_with_bits(
                    pb,
                    convert_uint256_to_bool_vector(h_sig)
                );
                g.generate_r1cs_witness(notes[0]);
            }
            BOOST_REQUIRE(pb.is_satisfied());
        }
        {
            libsnark::protoboard<FieldT> pb;
            {
                joinsplit_gadget<FieldT> g(pb);
                g.generate_r1cs_constraints();
                g.generate_r1cs_witness(
                    phi,
                    rt,
                    h_sig,
                    inputs,
                    notes,
                    vpub_old,
                    vpub_new
                );
            }
            BOOST_REQUIRE(pb.is_satisfied());
        }
} FC_LOG_AND_RETHROW() }


BOOST_AUTO_TEST_CASE( stealth_joinsplit_test )
{ try {\

    libsnark::init_alt_bn128_params();
    // The recipient's information.
    std::cout << "Generate recepient information..." << std::endl;
    stealth_spending_key recipient_key = stealth_spending_key::random();
    stealth_payment_address recipient_addr = recipient_key.address();

    // Create the commitment tree
    std::cout << "Create merkle tree..." << std::endl;
    merkle_tree tree;

    // Set up a JoinSplit description
    std::cout << "Prepare proof params..." << std::endl;
    fc::ecc::public_key ephemeralKey;
    fc::uint256 randomSeed;
    uint64_t vpub_old = 10;
    uint64_t vpub_new = 0;
    fc::uint256 pubKeyHash = random_uint256();
    boost::array<fc::uint256, 2> macs;
    boost::array<fc::uint256, 2> nullifiers;
    boost::array<fc::uint256, 2> commitments;
    fc::uint256 rt = tree.root();
    boost::array<binary, 2> ciphertexts;
    stealth_proof proof;

    std::cout << "Generate joinsplit..." << std::endl;
    std::unique_ptr<stealth_joinsplit> js = stealth_joinsplit::unopened();
    std::cout << "Load generated keys..." << std::endl;
    js->load_proving_key("proving.key");
    js->load_verifying_key("verifying.key");

    {
        boost::array<stealth_input, 2> inputs = {
            stealth_input(), // dummy input
            stealth_input() // dummy input
        };

        boost::array<stealth_output, 2> outputs = {
            stealth_output(recipient_addr, asset(10)),
            stealth_output() // dummy output
        };

        boost::array<stealth_note, 2> output_notes;

        // Perform the proof
        std::cout << "Perform the proof..." << std::endl;
        proof = js->prove(
            inputs,
            outputs,
            output_notes,
            ciphertexts,
            ephemeralKey,
            pubKeyHash,
            randomSeed,
            macs,
            nullifiers,
            commitments,
            vpub_old,
            vpub_new,
            rt
        );

        // Verify the transaction:
        std::cout << "Verify the transaction..." << std::endl;
        BOOST_REQUIRE(js->verify(
            proof,
            pubKeyHash,
            randomSeed,
            macs,
            nullifiers,
            commitments,
            vpub_old,
            vpub_new,
            rt
        ));
    }
    // Recipient should decrypt
    // Now the recipient should spend the money again
    std::cout << "Get hsig..." << std::endl;
    auto h_sig = js->h_sig(randomSeed, nullifiers, pubKeyHash);
    std::cout << "Create decryptor..." << std::endl;
    stealth_note_decryption decryptor(recipient_key.viewing_key().value);

    std::cout << "<decrypt note..." << std::endl;
    auto note_pt = stealth_note_plaintext::decrypt(
        decryptor,
        ciphertexts[0],
        ephemeralKey,
        h_sig,
        0
    );

    auto decrypted_note = note_pt.note(recipient_addr);

    BOOST_REQUIRE(decrypted_note.amount.amount == 10);

    // Insert the commitments from the last tx into the tree
    std::cout << "Insert the commitments from the last tx into the tree..." << std::endl;
    tree.append(commitments[0]);
    auto witness_recipient = tree.witness();
    tree.append(commitments[1]);
    witness_recipient.append(commitments[1]);
    vpub_old = 0;
    vpub_new = 1;
    rt = tree.root();
    pubKeyHash = random_uint256();

    {
        boost::array<stealth_input, 2> inputs = {
            stealth_input(), // dummy input
            stealth_input(witness_recipient, decrypted_note, recipient_key)
        };

        stealth_spending_key second_recipient = stealth_spending_key::random();
        stealth_payment_address second_addr = second_recipient.address();

        boost::array<stealth_output, 2> outputs = {
            stealth_output(second_addr, asset(9)),
            stealth_output() // dummy output
        };

        boost::array<stealth_note, 2> output_notes;

        // Perform the proof
        std::cout << "Perform the proof..." << std::endl;
        proof = js->prove(
            inputs,
            outputs,
            output_notes,
            ciphertexts,
            ephemeralKey,
            pubKeyHash,
            randomSeed,
            macs,
            nullifiers,
            commitments,
            vpub_old,
            vpub_new,
            rt
        );
    }

    // Verify the transaction:
    std::cout << "Verify the transaction..." << std::endl;
    BOOST_REQUIRE(js->verify(
        proof,
        pubKeyHash,
        randomSeed,
        macs,
        nullifiers,
        commitments,
        vpub_old,
        vpub_new,
        rt
    ));
} FC_LOG_AND_RETHROW() }


