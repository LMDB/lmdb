/* mdb_copy.c - memory-mapped database backup tool */
/*
 * Copyright 2012 Howard Chu, Symas Corp.
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
#include "lmdb.h"

int main(int argc,char * argv[])
{
	int rc;
	MDB_env *env;
	char *envname = argv[1];

	if (argc != 3) {
		fprintf(stderr, "usage: %s srcpath dstpath\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	rc = mdb_env_create(&env);

	rc = mdb_env_open(env, envname, MDB_RDONLY, 0);
	if (rc) {
		printf("mdb_env_open failed, error %d %s\n", rc, mdb_strerror(rc));
	} else {
		rc = mdb_env_copy(env, argv[2]);
		if (rc)
			printf("mdb_env_copy failed, error %d %s\n", rc, mdb_strerror(rc));
	}
	mdb_env_close(env);

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
