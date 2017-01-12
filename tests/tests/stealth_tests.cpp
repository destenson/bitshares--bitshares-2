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

#include <graphene/chain/database.hpp>
#include <graphene/chain/protocol/protocol.hpp>
#include <graphene/chain/exceptions.hpp>

#include <graphene/chain/protocol/stealth_zk.hpp>
#include <fc/crypto/sha256.hpp>
//#include "../common/database_fixture.hpp"
#include <iostream>

using namespace graphene::chain;

//BOOST_FIXTURE_TEST_SUITE( stealth_tests, database_fixture )

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



BOOST_AUTO_TEST_CASE( stealth_joinsplit_test )
{ try {

 /*   // The recipient's information.
    stealth_spending_key recipient_key = stealth_spending_key::random();
    stealth_payment_address recipient_addr = recipient_key.address();

    // Create the commitment tree
    merkle_tree tree;

    // Set up a JoinSplit description
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

    stealth_joinsplit js;

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
        proof = js.prove(
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
    BOOST_REQUIRE(js.verify(
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

    // Recipient should decrypt
    // Now the recipient should spend the money again
    auto h_sig = js.h_sig(randomSeed, nullifiers, pubKeyHash);
    stealth_note_decryption decryptor(recipient_key.viewing_key().value);

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
        proof = js.prove(
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
    BOOST_REQUIRE(js.verify(
        proof,
        pubKeyHash,
        randomSeed,
        macs,
        nullifiers,
        commitments,
        vpub_old,
        vpub_new,
        rt
    ));*/
} FC_LOG_AND_RETHROW() }

//BOOST_AUTO_TEST_SUITE_END()

