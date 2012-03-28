/* mfree.c - memory-mapped database freelist scanner */
/*
 * Copyright 2011 Howard Chu, Symas Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
#define _XOPEN_SOURCE 500		/* srandom(), random() */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "mdb.h"
#include "midl.h"

int main(int argc,char * argv[])
{
	int rc;
	MDB_env *env;
	MDB_dbi dbi;
	MDB_val key, data;
	MDB_txn *txn;
	MDB_stat mst;
	MDB_cursor *cursor;
	ID i, j, *iptr;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <pathname>\n", argv[0]);
		exit(1);
	}

	rc = mdb_env_create(&env);
	rc = mdb_env_open(env, argv[1], MDB_RDONLY, 0664);
	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	dbi = 0;
	rc = mdb_cursor_open(txn, dbi, &cursor);
	while ((rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
		printf("key: %p %zu, data: %p\n",
			key.mv_data,  *(ID *) key.mv_data,
			data.mv_data);
		iptr = data.mv_data;
		j = *iptr++;
		for (i=0; i<j; i++)
			printf(" %zu\n", iptr[i]);
	}
	mdb_cursor_close(cursor);
	mdb_txn_abort(txn);
	mdb_env_close(env);

	return 0;
}
