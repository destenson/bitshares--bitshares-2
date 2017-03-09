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
#include <graphene/chain/protocol/stealth.hpp>
#include <graphene/chain/stealth_evaluator.hpp>
#include <graphene/chain/database.hpp>

#include <fc/crypto/base58.hpp>
#include <fc/io/raw.hpp>
#include <fc/crypto/elliptic.hpp>

namespace graphene { namespace chain {

void transfer_to_stealth_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( amount.amount > 0 );

   // TODO: Verify stealth proof
}

share_type transfer_to_stealth_operation::calculate_fee( const fee_parameters_type& k )const
{
    return k.fee + outputs.size() * k.price_per_output;
}


void transfer_from_stealth_operation::validate()const
{
   FC_ASSERT( amount.amount > 0 );
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( inputs.size() > 0 );
   FC_ASSERT( amount.asset_id == fee.asset_id );


   // TODO: Verify stealth proof
}


/**
 *  If fee_payer = temp_account_id, then the fee is paid by the surplus balance of inputs-outputs and
 *  100% of the fee goes to the network.
 */
account_id_type stealth_transfer_operation::fee_payer()const
{
   return GRAPHENE_TEMP_ACCOUNT;
}


/**
 *  This method can be computationally intensive because it verifies that input commitments - output commitments add up to 0
 */
void stealth_transfer_operation::validate()const
{ try {
   FC_ASSERT( in.size(), "there must be at least one input" );
   FC_ASSERT( fc::ecc::verify_sum( in, out, net_public ), "", ("net_public", net_public) );

} FC_CAPTURE_AND_RETHROW( (*this) ) }

share_type stealth_transfer_operation::calculate_fee( const fee_parameters_type& k )const
{
    return k.fee + outputs.size() * k.price_per_output;
}


} } // graphene::chain

