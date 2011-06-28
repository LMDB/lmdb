#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "mdb.h"

int main(int argc,char * argv[])
{
	int i = 0, rc;
	MDB_env *env;
	MDB_db *db;
	MDB_val key, data;
	MDB_txn *txn;
	MDB_stat *mst;
	int count;
	int *values;
	char sval[32];

	srandom(time(NULL));

	    count = random()%512;		
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

	    for (i=0;i<count;i++) {	
			sprintf(sval, "%03x %d foo bar", values[i], values[i]);
			mdb_put(db, txn, &key, &data, 0);
	    }		
		rc = mdb_txn_commit(txn);
		rc = mdbenv_stat(env, &mst);

	    for (i= count - 1; i > -1; i-= (random()%5)) {	
			rc = mdb_txn_begin(env, 0, &txn);
			sprintf(sval, "%03x ", values[i]);
			rc = mdb_del(db, txn, &key, NULL);
			rc = mdb_txn_commit(txn);
	    }
	    free(values);
		rc = mdbenv_stat(env, &mst);
		mdb_close(db);
		mdbenv_close(env);

	return 0;
}
