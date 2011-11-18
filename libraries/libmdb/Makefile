CC	= gcc
W	= -W -Wall -Wno-unused-parameter -Wbad-function-cast
OPT = -O2 -g
CFLAGS	= -pthread $(OPT) $(W) $(XCFLAGS)
LDLIBS	=
SOLIBS	=

PROGS	= mdb_stat mtest mtest2 mtest3 mtest4 mtest5
all:	libmdb.a libmdb.so $(PROGS)

clean:
	rm -rf $(PROGS) *.[ao] *.so *~ testdb

test:	all
	mkdir testdb
	./mtest && ./mdb_stat testdb

libmdb.a:	mdb.o midl.o
	ar rs $@ mdb.o midl.o

libmdb.so:	mdb.o midl.o
	gcc -shared -o $@ mdb.o midl.o $(SOLIBS)

mdb_stat: mdb_stat.o libmdb.a
mtest:    mtest.o    libmdb.a
mtest2:	mtest2.o libmdb.a
mtest3:	mtest3.o libmdb.a
mtest4:	mtest4.o libmdb.a
mtest5:	mtest5.o libmdb.a
mtest6:	mtest6.o libmdb.a

mdb.o: mdb.c mdb.h midl.h
	$(CC) $(CFLAGS) -fPIC $(CPPFLAGS) -c mdb.c

midl.o: midl.c midl.h
	$(CC) $(CFLAGS) -fPIC $(CPPFLAGS) -c midl.c

%:	%.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

%.o:	%.c mdb.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<
