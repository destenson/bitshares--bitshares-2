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

#pragma once
#include <graphene/chain/protocol/base.hpp>
#include <graphene/chain/protocol/stealth_snark.hpp>

namespace graphene { namespace chain {


/**
 *  @class transfer_to_stealth_operation
 *  @ingroup stealth
 *  @brief Converts public account balance to a stealth balance
 */
struct transfer_to_stealth_operation : public base_operation
{
   struct fee_parameters_type {
      uint64_t fee              = 5*GRAPHENE_BLOCKCHAIN_PRECISION; ///< the cost to register the cheapest non-free account
      uint32_t price_per_output = 5*GRAPHENE_BLOCKCHAIN_PRECISION;
   };


   asset                 fee;
   asset                 amount;
   account_id_type       from;
   std::vector<stealth_description>  outputs;

   account_id_type fee_payer()const { return from; }
   void            validate()const;
   share_type      calculate_fee(const fee_parameters_type& )const;
};

/**
 *  @ingroup stealth
 *  @brief Converts stealth balance to a public account balance
 */
struct transfer_from_stealth_operation : public base_operation
{
   struct fee_parameters_type {
      uint64_t fee              = 5*GRAPHENE_BLOCKCHAIN_PRECISION; ///< the cost to register the cheapest non-free account
   };

   asset                 fee;
   asset                 amount;
   account_id_type       to;
   std::vector<stealth_description>   inputs;

   account_id_type fee_payer()const { return GRAPHENE_TEMP_ACCOUNT; }
   void            validate()const;

   void            get_required_authorities( vector<authority>& a )const
   {
      //for( const auto& in : inputs )
         //a.push_back( in.owner );
   }
};

/**
 *  @ingroup stealth
 *  @brief Transfers from stealth to stealth
 *
 */
struct stealth_transfer_operation : public base_operation
{
   struct fee_parameters_type {
      uint64_t fee              = 5*GRAPHENE_BLOCKCHAIN_PRECISION; ///< the cost to register the cheapest non-free account
      uint32_t price_per_output = 5*GRAPHENE_BLOCKCHAIN_PRECISION;
   };

   asset                 fee;
   std::vector<stealth_description>  transfers;

   /** graphene TEMP account */
   account_id_type fee_payer()const;
   void            validate()const;
   share_type      calculate_fee( const fee_parameters_type& k )const;

   void            get_required_authorities( vector<authority>& a )const
   {
      //for( const auto& in : transfers )
         //a.push_back( in.owner );
   }
};


///@} ;;endgroup stealth



} } // graphene::chain

FC_REFLECT( graphene::chain::transfer_to_stealth_operation,
            (fee)(amount)(from)(outputs) )
FC_REFLECT( graphene::chain::transfer_from_stealth_operation,
            (fee)(amount)(to)(inputs) )
FC_REFLECT( graphene::chain::stealth_transfer_operation,
            (fee)(transfers) )
FC_REFLECT( graphene::chain::transfer_to_stealth_operation::fee_parameters_type, (fee)(price_per_output) )
FC_REFLECT( graphene::chain::transfer_from_stealth_operation::fee_parameters_type, (fee) )
FC_REFLECT( graphene::chain::stealth_transfer_operation::fee_parameters_type, (fee)(price_per_output) )
