#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "mdb.h"

int main(int argc,char * argv[])
{
	int i = 0, rc;
	MDB_env *env;
	MDB_db *db;
	MDB_stat *mst;
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
	rc = mdb_open(env, NULL, NULL, 0, &db);
	if (rc) {
		printf("mdb_open failed, error %d\n", rc);
		exit(1);
	}
   
	rc = mdb_stat(db, &mst);
	printf("Page size: %u\n", mst->ms_psize);
	printf("Tree depth: %u\n", mst->ms_depth);
	printf("Branch pages: %lu\n", mst->ms_branch_pages);
	printf("Leaf pages: %lu\n", mst->ms_leaf_pages);
	printf("Overflow pages: %lu\n", mst->ms_overflow_pages);
	printf("Entries: %lu\n", mst->ms_entries);
	mdb_close(db);
	mdbenv_close(env);

	return 0;
}
