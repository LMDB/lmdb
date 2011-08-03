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

	if (argc > 2)
		subname = argv[2];
   
	rc = mdbenv_create(&env);
	rc = mdbenv_open(env, envname, MDB_RDONLY, 0);
	if (rc) {
		printf("mdbenv_open failed, error %d\n", rc);
		exit(1);
	}
	rc = mdb_txn_begin(env, 1, &txn);
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
	printf("Branch pages: %lu\n", mst.ms_branch_pages);
	printf("Leaf pages: %lu\n", mst.ms_leaf_pages);
	printf("Overflow pages: %lu\n", mst.ms_overflow_pages);
	printf("Entries: %lu\n", mst.ms_entries);
	mdb_txn_abort(txn);
	mdb_close(env, dbi);
	mdbenv_close(env);

	return 0;
}
