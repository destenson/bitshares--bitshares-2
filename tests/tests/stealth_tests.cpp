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
#include "../common/database_fixture.hpp"

using namespace graphene::chain;

BOOST_FIXTURE_TEST_SUITE( stealth_tests, database_fixture )
BOOST_AUTO_TEST_CASE( stealth_test )
{ try {

        fc::uint256 sk_enc = 
                stealth_note_encryption::generate_secret_key(uint256("21035d60bc1983e37950ce4803418a8fb33ea68d5b937ca382ecbae7564d6a07")));
        fc::uint256 pk_enc = 
                stealth_note_encryption::generate_public_key(sk_enc);
    
        stealth_note_encryption b;
        for (size_t i = 0; i < 100; i++)
        {
            stealth_note_encryption c;
    
            BOOST_REQUIRE(b.ephemeral_public_key != c.ephemeral_public_key, "the same default keys");
        }
    
        boost::array<unsigned char, 32> message;
        for (size_t i = 0; i < 32; i++) {
            // Fill the message with dummy data
            message[i] = (unsigned char) i;
        }
    
        for (int i = 0; i < 255; i++) {
            auto ciphertext = b.encrypt(pk_enc, message);
    
            {
                stealth_note_decryption decrypter(sk_enc);
    
                // Test decryption
                auto plaintext = decrypter.decrypt(ciphertext, b.ephemeral_public_key,
                                                   fc::uint256(), i);
                BOOST_REQUIRE(plaintext == message, "incorrect decrypt");
    
                // Test wrong nonce
                BOOST_REQUIRE_THROW(decrypter.decrypt(ciphertext, b.ephemeral_public_key,
                                                fc::uint256(), (i == 0) ? 1 : (i - 1)),
                              std::runtime_error);
            
                // Test wrong ephemeral key
                {
                    stealth_note_encryption c;
    
                    BOOST_REQUIRE_THROW(decrypter.decrypt(ciphertext,
                                                          c.ephemeral_public_key,
                                                   fc::uint256(), i), std::runtime_error);
                }
            
                // Test wrong seed
                BOOST_REQUIRE_THROW(decrypter.decrypt(ciphertext, b.ephemeral_public_key,
                                                      fc::uint256S("11035d60bc1983e37950ce4803418a8fb33ea68d5b937ca382ecbae7564d6a77"), i),
                                    std::runtime_error);
            
                // Test corrupted ciphertext
                ciphertext[10] ^= 0xff;
                BOOST_REQUIRE_THROW(decrypter.decrypt(ciphertext, b.ephemeral_public_key,
                                                      fc::uint256(), i),
                                    std::runtime_error);
                ciphertext[10] ^= 0xff;
            }
    
            {
                // Test wrong private key
                fc::uint256 sk_enc_2 = stealth_note_encryption::generate_privkey(uint252());
                stealth_note_decryption decrypter(sk_enc_2);
    
                BOOST_REQUIRE_THROW(decrypter.decrypt(ciphertext, b.ephemeral_public_key,
                                                      fc::uint256(), i),
                                    std::runtime_error);
            }
    
        }

        
} FC_LOG_AND_RETHROW() }



BOOST_AUTO_TEST_SUITE_END()

