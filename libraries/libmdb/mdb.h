/* mdb.h - memory-mapped database library header file */
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
 *
 * This code is derived from btree.c written by Martin Hedenfalk.
 *
 * Copyright (c) 2009, 2010 Martin Hedenfalk <martin@bzero.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef _MDB_H_
#define _MDB_H_

#include <sys/types.h>

struct MDB_cursor;
struct MDB_txn;
struct MDB_env;

typedef struct MDB_cursor MDB_cursor;
typedef struct MDB_txn MDB_txn;
typedef struct MDB_env MDB_env;

typedef unsigned int	MDB_dbi;

typedef struct MDB_val {
	void		*mv_data;
	size_t		 mv_size;
} MDB_val;

typedef int  (MDB_cmp_func)(const MDB_val *a, const MDB_val *b);
typedef void (MDB_rel_func)(void *ptr, void *oldptr);

#define MDB_NOOVERWRITE	0x10
#define MDB_NODUPDATA	0x20
#define MDB_DEL_DUP		0x40

typedef enum MDB_cursor_op {		/* cursor operations */
	MDB_FIRST,
	MDB_GET_BOTH,			/* position at key/data */
	MDB_GET_BOTH_RANGE,		/* position at key, nearest data */
	MDB_LAST,
	MDB_NEXT,
	MDB_NEXT_DUP,
	MDB_NEXT_NODUP,
	MDB_PREV,
	MDB_PREV_DUP,
	MDB_PREV_NODUP,
	MDB_SET,				/* position at key, or fail */
	MDB_SET_RANGE			/* position at given key */
} MDB_cursor_op;

/* return codes */
#define MDB_SUCCESS	 0
#define MDB_FAIL		-1
#define MDB_KEYEXIST	-2
#define MDB_NOTFOUND	-3
#define MDB_VERSION_MISMATCH	-4

/* DB flags */
#define MDB_REVERSEKEY	0x02		/* use reverse string keys */
#define MDB_DUPSORT		0x04		/* use sorted duplicates */
#define MDB_INTEGERKEY	0x08		/* numeric keys in native byte order */

/* environment flags */
#define MDB_FIXEDMAP	0x01		/* mmap at a fixed address */
#define MDB_NOSYNC		0x10000		/* don't fsync after commit */
#define MDB_RDONLY		0x20000		/* read only */

/* DB or env flags */
#define MDB_CREATE		0x40000		/* create if not present */

typedef struct MDB_stat {
	unsigned int	ms_psize;
	unsigned int	ms_depth;
	unsigned long	ms_branch_pages;
	unsigned long	ms_leaf_pages;
	unsigned long	ms_overflow_pages;
	unsigned long	ms_entries;
} MDB_stat;

int  mdbenv_create(MDB_env **env);
int  mdbenv_open(MDB_env *env, const char *path, unsigned int flags, mode_t mode);
int  mdbenv_stat(MDB_env *env, MDB_stat *stat);
int  mdbenv_sync(MDB_env *env);
void mdbenv_close(MDB_env *env);
int  mdbenv_get_flags(MDB_env *env, unsigned int *flags);
int  mdbenv_get_path(MDB_env *env, const char **path);
int  mdbenv_set_mapsize(MDB_env *env, size_t size);
int  mdbenv_set_maxreaders(MDB_env *env, int readers);
int  mdbenv_get_maxreaders(MDB_env *env, int *readers);
int  mdbenv_set_maxdbs(MDB_env *env, int dbs);

int  mdb_txn_begin(MDB_env *env, int rdonly, MDB_txn **txn);
int  mdb_txn_commit(MDB_txn *txn);
void mdb_txn_abort(MDB_txn *txn);

int  mdb_open(MDB_txn *txn, const char *name, unsigned int flags, MDB_dbi *dbi);
int  mdb_stat(MDB_txn *txn, MDB_dbi dbi, MDB_stat *stat);
void mdb_close(MDB_txn *txn, MDB_dbi dbi);

int  mdb_set_compare(MDB_txn *txn, MDB_dbi dbi, MDB_cmp_func *cmp);
int  mdb_set_dupsort(MDB_txn *txn, MDB_dbi dbi, MDB_cmp_func *cmp);
int  mdb_set_relfunc(MDB_txn *txn, MDB_dbi dbi, MDB_rel_func *rel);

int  mdb_get(MDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data);
int  mdb_put(MDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data,
			    unsigned int flags);
int  mdb_del(MDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data,
			    unsigned int flags);

int  mdb_cursor_open(MDB_txn *txn, MDB_dbi dbi, MDB_cursor **cursor);
void mdb_cursor_close(MDB_cursor *cursor);
int  mdb_cursor_get(MDB_cursor *cursor, MDB_val *key, MDB_val *data,
			    MDB_cursor_op op);
int  mdb_cursor_count(MDB_cursor *cursor, unsigned long *countp);

int  mdb_cmp(MDB_txn *txn, MDB_dbi dbi, const MDB_val *a, const MDB_val *b);

#endif /* _MDB_H_ */
