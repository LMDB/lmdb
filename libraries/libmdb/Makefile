CC	= gcc
W	= -W -Wall -Wno-unused-parameter -Wcast-qual -Wbad-function-cast
OPT = -O2 -g
CFLAGS	= -pthread $(OPT) $(W) $(XCFLAGS)
LDLIBS	=

PROGS	= mdb_stat mtest mtest2 mtest3
all:	libmdb.a $(PROGS)

clean:
	rm -rf $(PROGS) *.[ao] *~ testdb

test:	all
	mkdir testdb
	./mtest && ./mdb_stat testdb

libmdb.a:	mdb.o idl.o
	ar rs $@ mdb.o idl.o

mdb_stat: mdb_stat.o libmdb.a
mtest:    mtest.o    libmdb.a
mtest2:	mtest2.o libmdb.a
mtest3:	mtest3.o libmdb.a

%:	%.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

%.o:	%.c mdb.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<
