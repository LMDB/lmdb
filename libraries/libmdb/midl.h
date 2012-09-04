/**	@file midl.h
 *	@brief mdb ID List header file.
 *
 *	This file was originally part of back-bdb but has been
 *	modified for use in libmdb. Most of the macros defined
 *	in this file are unused, just left over from the original.
 *
 *	This file is only used internally in libmdb and its definitions
 *	are not exposed publicly.
 */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2012 The OpenLDAP Foundation.
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

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup internal	MDB Internals
 *	@{
 */

/** @defgroup idls	ID List Management
 *	@{
 */
	/** A generic ID number. These were entryIDs in back-bdb.
	 *	Preferably it should have the same size as a pointer.
	 */
typedef size_t MDB_ID;

	/** An IDL is an ID List, a sorted array of IDs. The first
	 * element of the array is a counter for how many actual
	 * IDs are in the list. In the original back-bdb code, IDLs are
	 * sorted in ascending order. For libmdb IDLs are sorted in
	 * descending order.
	 */
typedef MDB_ID *MDB_IDL;

#define	MDB_NOID	(~(MDB_ID)0)

/* IDL sizes - likely should be even bigger
 *   limiting factors: sizeof(ID), thread stack size
 */
#define	MDB_IDL_LOGN	16	/* DB_SIZE is 2^16, UM_SIZE is 2^17 */
#define MDB_IDL_DB_SIZE		(1<<MDB_IDL_LOGN)
#define MDB_IDL_UM_SIZE		(1<<(MDB_IDL_LOGN+1))
#define MDB_IDL_UM_SIZEOF	(MDB_IDL_UM_SIZE * sizeof(MDB_ID))

#define MDB_IDL_DB_MAX		(MDB_IDL_DB_SIZE-1)

#define MDB_IDL_UM_MAX		(MDB_IDL_UM_SIZE-1)

#define MDB_IDL_IS_RANGE(ids)	((ids)[0] == MDB_NOID)
#define MDB_IDL_RANGE_SIZE		(3)
#define MDB_IDL_RANGE_SIZEOF	(MDB_IDL_RANGE_SIZE * sizeof(MDB_ID))
#define MDB_IDL_SIZEOF(ids)		((MDB_IDL_IS_RANGE(ids) \
	? MDB_IDL_RANGE_SIZE : ((ids)[0]+1)) * sizeof(MDB_ID))

#define MDB_IDL_RANGE_FIRST(ids)	((ids)[1])
#define MDB_IDL_RANGE_LAST(ids)		((ids)[2])

#define MDB_IDL_RANGE( ids, f, l ) \
	do { \
		(ids)[0] = MDB_NOID; \
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
#define MDB_IDL_IS_ALL( range, ids ) ( (ids)[0] == MDB_NOID \
	&& (ids)[1] <= (range)[1] && (range)[2] <= (ids)[2] )

#define MDB_IDL_CPY( dst, src ) (memcpy( dst, src, MDB_IDL_SIZEOF( src ) ))

#define MDB_IDL_ID( bdb, ids, id ) MDB_IDL_RANGE( ids, id, ((bdb)->bi_lastid) )
#define MDB_IDL_ALL( bdb, ids ) MDB_IDL_RANGE( ids, 1, ((bdb)->bi_lastid) )

#define MDB_IDL_FIRST( ids )	( (ids)[1] )
#define MDB_IDL_LAST( ids )		( MDB_IDL_IS_RANGE(ids) \
	? (ids)[2] : (ids)[(ids)[0]] )

#define MDB_IDL_N( ids )		( MDB_IDL_IS_RANGE(ids) \
	? ((ids)[2]-(ids)[1])+1 : (ids)[0] )

#if 0	/* superseded by append/sort */
	/** Insert an ID into an IDL.
	 * @param[in,out] ids	The IDL to insert into.
	 * @param[in] id	The ID to insert.
	 * @return	0 on success, -1 if the ID was already present in the IDL.
	 */
int mdb_midl_insert( MDB_IDL ids, MDB_ID id );
#endif

	/** Allocate an IDL.
	 * Allocates memory for an IDL of a default size.
	 * @return	IDL on success, NULL on failure.
	 */
MDB_IDL mdb_midl_alloc();

	/** Free an IDL.
	 * @param[in] ids	The IDL to free.
	 */
void mdb_midl_free(MDB_IDL ids);

	/** Shrink an IDL.
	 * Return the IDL to the default size if it has grown larger.
	 * @param[in,out] idp	Address of the IDL to shrink.
	 * @return	0 on no change, non-zero if shrunk.
	 */
int mdb_midl_shrink(MDB_IDL *idp);

	/** Append an ID onto an IDL.
	 * @param[in,out] idp	Address of the IDL to append to.
	 * @param[in] id	The ID to append.
	 * @return	0 on success, -1 if the IDL is too large.
	 */
int mdb_midl_append( MDB_IDL *idp, MDB_ID id );

	/** Append an IDL onto an IDL.
	 * @param[in,out] idp	Address of the IDL to append to.
	 * @param[in] app	The IDL to append.
	 * @return	0 on success, -1 if the IDL is too large.
	 */
int mdb_midl_append_list( MDB_IDL *idp, MDB_IDL app );

	/** Sort an IDL.
	 * @param[in,out] ids	The IDL to sort.
	 */
void mdb_midl_sort( MDB_IDL ids );

	/** An ID2 is an ID/pointer pair.
	 */
typedef struct MDB_ID2 {
	MDB_ID mid;		/**< The ID */
	void *mptr;		/**< The pointer */
} MDB_ID2;

	/** An ID2L is an ID2 List, a sorted array of ID2s.
	 * The first element's \b mid member is a count of how many actual
	 * elements are in the array. The \b mptr member of the first element is unused.
	 * The array is sorted in ascending order by \b mid.
	 */
typedef MDB_ID2 *MDB_ID2L;

	/** Search for an ID in an ID2L.
	 * @param[in] ids	The ID2L to search.
	 * @param[in] id	The ID to search for.
	 * @return	The index of the first ID2 whose \b mid member is greater than or equal to \b id.
	 */
unsigned mdb_mid2l_search( MDB_ID2L ids, MDB_ID id );


	/** Insert an ID2 into a ID2L.
	 * @param[in,out] ids	The ID2L to insert into.
	 * @param[in] id	The ID2 to insert.
	 * @return	0 on success, -1 if the ID was already present in the ID2L.
	 */
int mdb_mid2l_insert( MDB_ID2L ids, MDB_ID2 *id );

	/** Append an ID2 into a ID2L.
	 * @param[in,out] ids	The ID2L to append into.
	 * @param[in] id	The ID2 to append.
	 * @return	0 on success, -2 if the ID2L is too big.
	 */
int mdb_mid2l_append( MDB_ID2L ids, MDB_ID2 *id );

/** @} */
/** @} */
#ifdef __cplusplus
}
#endif
#endif	/* _MDB_MIDL_H_ */
