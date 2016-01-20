cmake_minimum_required(VERSION 2.8)

# Can help https://github.com/nslay/liblmdb/blob/master/CMakeLists.txt

project(LMDB C)

include(CTest)

if (CMAKE_BUILD_TYPE MATCHES Debug)
   add_definitions(-DMDB_DEBUG)
endif(CMAKE_BUILD_TYPE MATCHES Debug)

include_directories(${PROJECT_SOURCE_DIR})

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")

file(GLOB TEST_SOURCES mtest*.c)
set(LIB_SOURCES        lmdb.h mdb.c midl.c midl.h)

add_library(lmdb_static STATIC ${LIB_SOURCES})
add_library(lmdb_share SHARED ${LIB_SOURCES})

add_executable(mdb_copy mdb_copy.c)

if (WIN32)
    include_directories(${PROJECT_SOURCE_DIR}/windows)
    add_executable(mdb_stat mdb_stat.c windows/getopt.c)
    add_executable(mdb_dump mdb_dump.c windows/getopt.c)
    add_executable(mdb_load mdb_load.c windows/getopt.c)
else ()
    add_executable(mdb_stat mdb_stat.c)
    add_executable(mdb_dump mdb_dump.c)
    add_executable(mdb_load mdb_load.c)
endif()

target_link_libraries(mdb_copy lmdb_static)
target_link_libraries(mdb_stat lmdb_static)
target_link_libraries(mdb_dump lmdb_static)
target_link_libraries(mdb_load lmdb_static)

set_target_properties(lmdb_static lmdb_share PROPERTIES OUTPUT_NAME lmdb)

enable_testing()

set(testdb_dir ${CMAKE_BINARY_DIR}/testdb)
if (NOT EXISTS  ${testdb_dir})
    file(MAKE_DIRECTORY ${testdb_dir})
endif(NOT EXISTS ${testdb_dir})

macro(lmdb_tests)
    foreach(t ${ARGN})
        if (t MATCHES mtest6.c AND NOT CMAKE_BUILD_TYPE MATCHES Debug)
            continue()
        endif()
        get_filename_component(_tname ${t} NAME_WE)
        add_executable(${_tname} ${t})
        target_link_libraries(${_tname} lmdb_static)
        add_test(${t} ${_tname})
    endforeach()
endmacro()

lmdb_tests(${TEST_SOURCES})

file(GLOB mdb_man_1 *.1)
install(FILES   ${PROJECT_SOURCE_DIR}/lmdb.h        DESTINATION include)
install(FILES   ${mdb_man_1}                        DESTINATION man/man1)
install(TARGETS lmdb_static lmdb_share              DESTINATION lib)
install(TARGETS mdb_stat mdb_copy mdb_dump mdb_load DESTINATION bin)
