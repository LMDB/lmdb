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
#include <time.h>
#include "mdb.h"

int main(int argc,char * argv[])
{
	int rc;
	MDB_env *env;
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_stat mst;
	char *envname = argv[1];
	char *subname = NULL;

	rc = mdb_env_create(&env);

	if (argc > 2) {
		mdb_env_set_maxdbs(env, 4);
		subname = argv[2];
	}

	rc = mdb_env_open(env, envname, MDB_RDONLY, 0);
	if (rc) {
		printf("mdb_env_open failed, error %d\n", rc);
		exit(1);
	}
	rc = mdb_txn_begin(env, NULL, 1, &txn);
	if (rc) {
		printf("mdb_txn_begin failed, error %d\n", rc);
		exit(1);
	}
	rc = mdb_open(txn, subname, 0, &dbi);
	if (rc) {
		printf("mdb_open failed, error %d\n", rc);
		exit(1);
	}
   
	rc = mdb_stat(txn, dbi, &mst);
	printf("Page size: %u\n", mst.ms_psize);
	printf("Tree depth: %u\n", mst.ms_depth);
	printf("Branch pages: %zu\n", mst.ms_branch_pages);
	printf("Leaf pages: %zu\n", mst.ms_leaf_pages);
	printf("Overflow pages: %zu\n", mst.ms_overflow_pages);
	printf("Entries: %zu\n", mst.ms_entries);
	mdb_close(env, dbi);
	mdb_txn_abort(txn);
	mdb_env_close(env);

	return 0;
}
