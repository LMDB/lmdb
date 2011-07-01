CC	= gcc
W	= -W -Wall -Wno-unused-parameter -Wcast-qual -Wbad-function-cast
OPT = -O2 -g
CFLAGS	= -pthread $(OPT) $(W) $(XCFLAGS)
LDLIBS	= -lssl

all:	mtest mdb_stat

clean:
	rm -f mtest mdb_stat *.[ao] *~ testdb

test:	all
	./mtest && ./mdb_stat testdb

mdb_stat: mdb_stat.o mdb.o idl.o
mtest:    mtest.o    mdb.o idl.o

%:	%.o mdb.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

%.o:	%.c mdb.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<
