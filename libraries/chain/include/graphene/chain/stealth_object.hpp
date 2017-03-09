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

#include <graphene/chain/protocol/authority.hpp>
#include <graphene/chain/protocol/types.hpp>

#include <graphene/db/object.hpp>
#include <graphene/db/generic_index.hpp>

#include <graphene/chain/protocol/stealth_zk.hpp>

namespace graphene { namespace chain {

/**
 * @class stealth_balance_object
 * @brief tracks a stealth balance commitment
 * @ingroup object
 * @ingroup protocol
 */
class stealth_balance_object : public graphene::db::abstract_object<stealth_balance_object>
{
   public:
      static const uint8_t space_id = implementation_ids;
      static const uint8_t type_id  = impl_stealth_balance_object_type;

      stealth_description                     description;
      asset_id_type                           asset_id;
      authority                               owner;
};

struct by_asset;
struct by_owner;
struct by_commitment;

/**
 * @ingroup object_index
 */
typedef multi_index_container<
   stealth_balance_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_commitment>, member<stealth_balance_object, stealth_description, &stealth_balance_object::description> >
   >
> stealth_balance_object_multi_index_type;
typedef generic_index<stealth_balance_object, stealth_balance_object_multi_index_type> stealth_balance_index;

} } // graphene::chain

FC_REFLECT_DERIVED( graphene::chain::stealth_balance_object, (graphene::db::object), (description)(asset_id)(owner) )
