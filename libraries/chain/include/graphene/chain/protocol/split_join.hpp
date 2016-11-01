#pragma once
#include <graphene/chain/protocol/base.hpp>

namespace graphene { namespace chain {

struct split_join_operation : public base_operation
{
   struct fee_parameters_type {};

   asset fee;   // always zero
   account_id_type account_id;
   share_type amount;

   account_id_type fee_payer()const { return account_id; }
   void validate()const { FC_ASSERT( false ); }
   share_type calculate_fee(const fee_parameters_type& k)const { return 0; }
};

} }

FC_REFLECT( graphene::chain::split_join_operation::fee_parameters_type,  )

FC_REFLECT( graphene::chain::split_join_operation, (fee)(account_id)(amount) )
