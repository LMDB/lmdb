#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "mdb.h"

int main(int argc,char * argv[])
{
	int i = 0, j = 0, rc;
	MDB_env *env;
	MDB_db *db;
	MDB_val key, data;
	MDB_txn *txn;
	MDB_stat *mst;
	MDB_cursor *cursor;
	int count;
	int *values;
	char sval[32];

	srandom(time(NULL));

	    count = (random()%384) + 64;
	    values = (int *)malloc(count*sizeof(int));

	    for(i = 0;i<count;i++) {
			values[i] = random()%1024;
	    }
    
		rc = mdbenv_create(&env, 10485760);
		rc = mdbenv_open(env, "./testdb", MDB_FIXEDMAP|MDB_NOSYNC, 0664);
		rc = mdb_txn_begin(env, 0, &txn);
		rc = mdb_open(env, txn, NULL, 0, &db);
   
		key.mv_size = sizeof(int);
		key.mv_data = sval;
		data.mv_size = sizeof(sval);
		data.mv_data = sval;

		printf("Adding %d values\n", count);
	    for (i=0;i<count;i++) {	
			sprintf(sval, "%03x %d foo bar", values[i], values[i]);
			rc = mdb_put(db, txn, &key, &data, MDB_NOOVERWRITE);
			if (rc) j++;
	    }
		if (j) printf("%d duplicates skipped\n", j);
		rc = mdb_txn_commit(txn);
		rc = mdbenv_stat(env, &mst);

		rc = mdb_cursor_open(db, NULL, &cursor);
		while (rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT) == 0) {
			printf("key: %.*s, data: %.*s\n",
				key.mv_size, key.mv_data, data.mv_size, data.mv_data);
		}
		mdb_cursor_close(cursor);

		j=0;
	    for (i= count - 1; i > -1; i-= (random()%5)) {	
			j++;
			rc = mdb_txn_begin(env, 0, &txn);
			key.mv_data = sval;
			sprintf(sval, "%03x ", values[i]);
			rc = mdb_del(db, txn, &key, NULL);
			if (rc) {
				j--;
				mdb_txn_abort(txn);
			} else {
				rc = mdb_txn_commit(txn);
			}
	    }
	    free(values);
		printf("Deleted %d values\n", j);

		rc = mdbenv_stat(env, &mst);
		rc = mdb_cursor_open(db, NULL, &cursor);
		while (rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT) == 0) {
			printf("key: %.*s, data: %.*s\n",
				key.mv_size, key.mv_data, data.mv_size, data.mv_data);
		}
		mdb_cursor_close(cursor);

		mdb_close(db);
		mdbenv_close(env);

	return 0;
}
