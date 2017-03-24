
TEMPLATE =lib
CONFIG += thread static
CONFIG -= qt

TARGET = lmdbxx

HEADERS = lmdb.h lmdb++.h midl.h
SOURCES = mdb.c midl.c


win32:{
    LIBS += -lNtdll
}

DISTFILES += \
    CMakeLists.txt \
    CMakeExample.cmake \
    cmake/lmdbxxConfig.cmake
