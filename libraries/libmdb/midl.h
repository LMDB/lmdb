/* idl.h - ldap bdb back-end ID list header file */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2011 The OpenLDAP Foundation.
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

#ifndef _MDB_MIDL_H_
#define _MDB_MIDL_H_

#define	ID	unsigned long
#define	NOID	(~(ID)0)

/* IDL sizes - likely should be even bigger
 *   limiting factors: sizeof(ID), thread stack size
 */
#define	MDB_IDL_LOGN	16	/* DB_SIZE is 2^16, UM_SIZE is 2^17 */
#define MDB_IDL_DB_SIZE		(1<<MDB_IDL_LOGN)
#define MDB_IDL_UM_SIZE		(1<<(MDB_IDL_LOGN+1))
#define MDB_IDL_UM_SIZEOF	(MDB_IDL_UM_SIZE * sizeof(ID))

#define MDB_IDL_DB_MAX		(MDB_IDL_DB_SIZE-1)

#define MDB_IDL_UM_MAX		(MDB_IDL_UM_SIZE-1)

#define MDB_IDL_IS_RANGE(ids)	((ids)[0] == NOID)
#define MDB_IDL_RANGE_SIZE		(3)
#define MDB_IDL_RANGE_SIZEOF	(MDB_IDL_RANGE_SIZE * sizeof(ID))
#define MDB_IDL_SIZEOF(ids)		((MDB_IDL_IS_RANGE(ids) \
	? MDB_IDL_RANGE_SIZE : ((ids)[0]+1)) * sizeof(ID))

#define MDB_IDL_RANGE_FIRST(ids)	((ids)[1])
#define MDB_IDL_RANGE_LAST(ids)		((ids)[2])

#define MDB_IDL_RANGE( ids, f, l ) \
	do { \
		(ids)[0] = NOID; \
		(ids)[1] = (f);  \
		(ids)[2] = (l);  \
	} while(0)

#define MDB_IDL_ZERO(ids) \
	do { \
		(ids)[0] = 0; \
		(ids)[1] = 0; \
		(ids)[2] = 0; \
	} while(0)

#define MDB_IDL_IS_ZERO(ids) ( (ids)[0] == 0 )
#define MDB_IDL_IS_ALL( range, ids ) ( (ids)[0] == NOID \
	&& (ids)[1] <= (range)[1] && (range)[2] <= (ids)[2] )

#define MDB_IDL_CPY( dst, src ) (memcpy( dst, src, MDB_IDL_SIZEOF( src ) ))

#define MDB_IDL_ID( bdb, ids, id ) MDB_IDL_RANGE( ids, id, ((bdb)->bi_lastid) )
#define MDB_IDL_ALL( bdb, ids ) MDB_IDL_RANGE( ids, 1, ((bdb)->bi_lastid) )

#define MDB_IDL_FIRST( ids )	( (ids)[1] )
#define MDB_IDL_LAST( ids )		( MDB_IDL_IS_RANGE(ids) \
	? (ids)[2] : (ids)[(ids)[0]] )

#define MDB_IDL_N( ids )		( MDB_IDL_IS_RANGE(ids) \
	? ((ids)[2]-(ids)[1])+1 : (ids)[0] )

int mdb_midl_insert( ID *ids, ID id );

typedef struct MIDL2 {
	ID mid;
	void *mptr;
} MIDL2;

unsigned mdb_midl2_search( MIDL2 *ids, MIDL2 *id );
int mdb_midl2_insert( MIDL2 *ids, MIDL2 *id );

#endif	/* _MDB_MIDL_H_ */
