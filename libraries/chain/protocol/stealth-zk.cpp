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
#include <graphene/chain/protocol/stealth-zk.hpp>
#include <graphene/chain/database.hpp>

namespace graphene { namespace chain {

fc::uint256 stealth_payment_address::hash() const
{
    return fc::sha256::hash(fc::raw::pack( *this ));
}

fc::uint256 stealth_viewing_key::transmission_key() const
{
    return stealth_note_encryption::generate_public_key(*this);
}

stealth_spending_key stealth_spending_key::random()
{
    return stealth_spending_key({});
}

stealth_viewing_key stealth_spending_key::viewing_key() const
{
    return stealth_viewing_key(
        {stealth_note_encryption::generate_secret_key(*this)}
                );
}

stealth_payment_address stealth_spending_key::address() const
{

}


}}

