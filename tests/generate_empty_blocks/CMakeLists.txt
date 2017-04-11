add_executable( generate_empty_blocks main.cpp )
if( UNIX AND NOT APPLE )
  set(rt_library rt )
endif()

target_link_libraries( generate_empty_blocks
                       PRIVATE graphene_app graphene_egenesis_none graphene_chain fc libsnark gmp sodium ${CMAKE_DL_LIBS} ${PLATFORM_SPECIFIC_LIBS} )

install( TARGETS
   generate_empty_blocks

   RUNTIME DESTINATION bin
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
)
