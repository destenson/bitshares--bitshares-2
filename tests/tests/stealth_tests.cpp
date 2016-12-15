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

        binary h_sig = random_binary(256);
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
                                                      random_binary(256), i),
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

    binary h_sig = random_binary(256);
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

//BOOST_AUTO_TEST_SUITE_END()

