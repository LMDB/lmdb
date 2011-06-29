CC	= gcc
W	= -W -Wall -Wno-unused-parameter -Wcast-qual -Wbad-function-cast
CFLAGS	= -pthread -O2 -g $(W) $(XCFLAGS)
LDLIBS	= -lssl

all:	mtest mdb_stat

clean:
	rm -f mtest mdb_stat *.[ao] *~ testdb

test:	all
	./mtest && ./mdb_stat testdb

mdb_stat: mdb_stat.o mdb.o
mtest:    mtest.o    mdb.o

%:	%.o mdb.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

%.o:	%.c mdb.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<
