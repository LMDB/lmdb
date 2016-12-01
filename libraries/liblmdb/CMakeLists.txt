#cmake_minimum_required(VERSION 2.8.12)

#set(PrjName "mylmdb")

#project(${PrjName})


add_library(mylmdb SHARED mdb.c midl.c lmdb.h midl.h)


set(mods 
mdb_stat 
mdb_copy 
mdb_dump 
mdb_load 
mtest
mtest2
mtest3
mtest4
mtest5
)


foreach( mod  ${mods} )
    if(BUILD_ANDROID)
        add_library(${mod} SHARED ${mod}.c)
        target_link_libraries( ${mod} mylmdb )
    else()
        add_executable(${mod} ${mod}.c )
        target_link_libraries( ${mod} mylmdb pthread)
    endif()


    if (MSVC)
    else()
    endif()
endforeach()

