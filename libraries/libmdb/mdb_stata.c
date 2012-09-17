/* mdb_stat.c - memory-mapped database status tool */
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mdb.h"

int main(int argc,char * argv[])
{
	int rc;
	MDB_env *env;
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_stat mst;
	MDB_cursor *cursor;
	MDB_val key;
	char *envname = argv[1];

	rc = mdb_env_create(&env);

	mdb_env_set_maxdbs(env, 4);

	rc = mdb_env_open(env, envname, MDB_RDONLY, 0);
	if (rc) {
		printf("mdb_env_open failed, error %d\n", rc);
		goto env_close;
	}
	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (rc) {
		printf("mdb_txn_begin failed, error %d\n", rc);
		goto env_close;
	}
	rc = mdb_open(txn, NULL, 0, &dbi);
	if (rc) {
		printf("mdb_open failed, error %d\n", rc);
		goto txn_abort;
	}
   
	rc = mdb_stat(txn, dbi, &mst);
	printf("Page size: %u\n", mst.ms_psize);
	printf("Tree depth: %u\n", mst.ms_depth);
	printf("Branch pages: %zu\n", mst.ms_branch_pages);
	printf("Leaf pages: %zu\n", mst.ms_leaf_pages);
	printf("Overflow pages: %zu\n", mst.ms_overflow_pages);
	printf("Entries: %zu\n", mst.ms_entries);

	rc = mdb_cursor_open(txn, dbi, &cursor);
	while ((rc = mdb_cursor_get(cursor, &key, NULL, MDB_NEXT)) == 0) {
		char *str = malloc(key.mv_size+1);
		MDB_dbi db2;
		memcpy(str, key.mv_data, key.mv_size);
		str[key.mv_size] = '\0';
		printf("\n%s\n", str);
		rc = mdb_open(txn, str, 0, &db2);
		if (rc) break;
		free(str);
		rc = mdb_stat(txn, db2, &mst);
		printf("Tree depth: %u\n", mst.ms_depth);
		printf("Branch pages: %zu\n", mst.ms_branch_pages);
		printf("Leaf pages: %zu\n", mst.ms_leaf_pages);
		printf("Overflow pages: %zu\n", mst.ms_overflow_pages);
		printf("Entries: %zu\n", mst.ms_entries);
		mdb_close(env, db2);
	}
	mdb_cursor_close(cursor);
	mdb_close(env, dbi);
txn_abort:
	mdb_txn_abort(txn);
env_close:
	mdb_env_close(env);

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
