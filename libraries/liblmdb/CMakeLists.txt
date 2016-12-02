cmake_minimum_required(VERSION 2.8.12)

set(ProName "lmdbxx")
#set(CMAKE_INSTALL_PREFIX "F:/sandbox-orm/local")
project(${ProName})


set(CMAKE_INCLUDE_CURRENT_DIR ON)

set("${ProName}_VERSION" 0.9.18)
include(GenerateExportHeader)

add_library(${ProName} STATIC mdb.c midl.c lmdb.h midl.h)
if( MSVC )
    target_link_libraries(${ProName}
               Ntdll.lib
        )
endif()
generate_export_header(${ProName})
target_include_directories( "${ProName}"
     PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
     PUBLIC
        $<INSTALL_INTERFACE:include>
)

install(TARGETS  ${ProName} EXPORT  "${ProName}Targets"
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES DESTINATION include
)

install(
  FILES
    lmdb.h
    midl.h
    lmdb++.h
  DESTINATION
    include
  COMPONENT
    Devel
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/cmake/${ProName}ConfigVersion.cmake"
  VERSION "${ProName}_VERSION"
  COMPATIBILITY AnyNewerVersion
)
export(
    EXPORT  "${ProName}Targets"
    FILE "${CMAKE_CURRENT_BINARY_DIR}/cmake/${ProName}Targets.cmake"
    NAMESPACE ${ProName}::
)
configure_file(cmake/${ProName}Config.cmake
  "${CMAKE_CURRENT_BINARY_DIR}/cmake/${ProName}Config.cmake"
  COPYONLY
)

set(ConfigPackageLocation lib/cmake/${ProName})
install(EXPORT ${ProName}Targets
  FILE
    ${ProName}Targets.cmake
  NAMESPACE
    ${ProName}::
  DESTINATION
    ${ConfigPackageLocation}
)
install(
  FILES
    cmake/${ProName}Config.cmake
    "${CMAKE_CURRENT_BINARY_DIR}/cmake/${ProName}ConfigVersion.cmake"
  DESTINATION
    ${ConfigPackageLocation}
  COMPONENT
    Devel
)

#============== example ====================
set(lmdbmod
    mdb_stat
    mdb_copy
    mdb_dump
    mdb_load
)
foreach( mod  ${lmdbmod} )
    if (MSVC)
        add_executable(${mod} ${mod}.c wingetopt.c wingetopt.h)
        target_link_libraries( ${mod} ${ProName} )
    else()
        add_executable(${mod} ${mod}.c )
        target_link_libraries( ${mod} ${ProName} pthread)
    endif()
endforeach()

set(mtests
    mtest
    mtest2
    mtest3
    mtest4
    mtest5
)
foreach( test  ${mtests} )
    add_executable(${test} ${test}.c )
    if (MSVC)
        target_link_libraries( ${test} ${ProName} )
    else()
        target_link_libraries( ${test} ${ProName} pthread)
    endif()
endforeach()

#[[
add_executable(example example.cpp)
target_link_libraries(example ${ProName})
]]
