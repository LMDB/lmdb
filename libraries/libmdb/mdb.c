/** @file mdb.c
 *	@brief memory-mapped database library
 *
 *	A Btree-based database management library modeled loosely on the
 *	BerkeleyDB API, but much simplified.
 */
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/uio.h>
#include <sys/mman.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#include <fcntl.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef _WIN32
#include <pthread.h>
#endif

#include "mdb.h"
#include "midl.h"

/** @defgroup internal	MDB Internals
 *	@{
 */
/** @defgroup compat	Windows Compatibility Macros
 *	@{
 */
#ifdef _WIN32
#define pthread_t	DWORD
#define pthread_mutex_t	HANDLE
#define pthread_key_t	DWORD
#define pthread_self()	GetCurrentThreadId()
#define pthread_key_create(x,y)	*(x) = TlsAlloc()
#define pthread_key_delete(x)	TlsFree(x)
#define pthread_getspecific(x)	TlsGetValue(x)
#define pthread_setspecific(x,y)	TlsSetValue(x,y)
#define pthread_mutex_unlock(x)	ReleaseMutex(x)
#define pthread_mutex_lock(x)	WaitForSingleObject(x, INFINITE)
#define LOCK_MUTEX_R(env)	pthread_mutex_lock(env->me_rmutex)
#define UNLOCK_MUTEX_R(env)	pthread_mutex_unlock(env->me_rmutex)
#define LOCK_MUTEX_W(env)	pthread_mutex_lock(env->me_wmutex)
#define UNLOCK_MUTEX_W(env)	pthread_mutex_unlock(env->me_wmutex)
#define getpid()	GetCurrentProcessId()
#define	fdatasync(fd)	!FlushFileBuffers(fd)
#define	ErrCode()	GetLastError()
#define GetPageSize(x)	{SYSTEM_INFO si; GetSystemInfo(&si); (x) = si.dwPageSize;}
#define	close(fd)	CloseHandle(fd)
#define	munmap(ptr,len)	UnmapViewOfFile(ptr)
#else
#define LOCK_MUTEX_R(env)	pthread_mutex_lock(&env->me_txns->mti_mutex)
#define UNLOCK_MUTEX_R(env)	pthread_mutex_unlock(&env->me_txns->mti_mutex)
#define LOCK_MUTEX_W(env)	pthread_mutex_lock(&env->me_txns->mti_wmutex)
#define UNLOCK_MUTEX_W(env)	pthread_mutex_unlock(&env->me_txns->mti_wmutex)
#define	ErrCode()	errno
#define	HANDLE	int
#define INVALID_HANDLE_VALUE	-1
#define	GetPageSize(x)	(x) = sysconf(_SC_PAGE_SIZE)
#endif

/** @} */

#ifndef _WIN32
/* Note: If O_DSYNC is undefined but exists in /usr/include,
 * preferably set some compiler flag to get the definition.
 * Otherwise compile with the less efficient -DMDB_DSYNC=O_SYNC.
 */
#ifndef MDB_DSYNC
# define MDB_DSYNC	O_DSYNC
#endif
#endif

typedef ULONG		pgno_t;

#ifndef DEBUG
#define DEBUG 0
#endif

#if !(__STDC_VERSION__ >= 199901L || defined(__GNUC__))
# define DPRINTF	(void)	/* Vararg macros may be unsupported */
#elif DEBUG
# define DPRINTF(fmt, ...)	/* Requires 2 or more args */ \
	fprintf(stderr, "%s:%d:(%p) " fmt "\n", __func__, __LINE__, pthread_self(), __VA_ARGS__)
#else
# define DPRINTF(fmt, ...)	((void) 0)
#endif
#define DPUTS(arg)	DPRINTF("%s", arg)

#define PAGESIZE	 4096
#define MDB_MINKEYS	 2
#define MDB_MAGIC	 0xBEEFC0DE
#define MDB_VERSION	 1
#define MAXKEYSIZE	 511
#if DEBUG
#define	KBUF	(MAXKEYSIZE*2+1)
#define DKBUF	char kbuf[KBUF]
#define	DKEY(x)	mdb_dkey(x, kbuf)
#else
#define	DKBUF
#define DKEY(x)
#endif

/* The DB view is always consistent because all writes are wrapped in
 * the wmutex. Finer-grained locks aren't necessary.
 */
#ifndef	LAZY_LOCKS
#define	LAZY_LOCKS	1
#endif
#if	LAZY_LOCKS
#define	LAZY_MUTEX_LOCK(x)
#define	LAZY_MUTEX_UNLOCK(x)
#define	LAZY_RWLOCK_UNLOCK(x)
#define	LAZY_RWLOCK_WRLOCK(x)
#define	LAZY_RWLOCK_RDLOCK(x)
#define	LAZY_RWLOCK_DEF(x)
#define	LAZY_RWLOCK_INIT(x,y)
#define	LAZY_RWLOCK_DESTROY(x)
#else
#define	LAZY_MUTEX_LOCK(x)		pthread_mutex_lock(x)
#define	LAZY_MUTEX_UNLOCK(x)	pthread_mutex_unlock(x)
#define	LAZY_RWLOCK_UNLOCK(x)	pthread_rwlock_unlock(x)
#define	LAZY_RWLOCK_WRLOCK(x)	pthread_rwlock_wrlock(x)
#define	LAZY_RWLOCK_RDLOCK(x)	pthread_rwlock_rdlock(x)
#define	LAZY_RWLOCK_DEF(x)		pthread_rwlock_t	x
#define	LAZY_RWLOCK_INIT(x,y)	pthread_rwlock_init(x,y)
#define	LAZY_RWLOCK_DESTROY(x)	pthread_rwlock_destroy(x)
#endif

#define P_INVALID	 (~0UL)

#define F_ISSET(w, f)	 (((w) & (f)) == (f))

typedef uint16_t	 indx_t;

#define DEFAULT_READERS	126
#define DEFAULT_MAPSIZE	1048576

/* Lock descriptor stuff */
#ifndef CACHELINE
#define CACHELINE	64	/* most CPUs. Itanium uses 128 */
#endif

typedef struct MDB_rxbody {
	ULONG		mrb_txnid;
	pid_t		mrb_pid;
	pthread_t	mrb_tid;
} MDB_rxbody;

typedef struct MDB_reader {
	union {
		MDB_rxbody mrx;
#define	mr_txnid	mru.mrx.mrb_txnid
#define	mr_pid	mru.mrx.mrb_pid
#define	mr_tid	mru.mrx.mrb_tid
		/* cache line alignment */
		char pad[(sizeof(MDB_rxbody)+CACHELINE-1) & ~(CACHELINE-1)];
	} mru;
} MDB_reader;

typedef struct MDB_txbody {
	uint32_t	mtb_magic;
	uint32_t	mtb_version;
/* For POSIX the actual mutexes reside in shared memory.
 * On Windows, mutexes are allocated by the kernel; we store
 * the name in shared memory so that other processes can
 * grab them.
 */
#ifdef _WIN32
	char	mtb_rmname[32];
#else
	pthread_mutex_t	mtb_mutex;
#endif
	ULONG		mtb_txnid;
	uint32_t	mtb_numreaders;
	uint32_t	mtb_me_toggle;
} MDB_txbody;

typedef struct MDB_txninfo {
	union {
		MDB_txbody mtb;
#define mti_magic	mt1.mtb.mtb_magic
#define mti_version	mt1.mtb.mtb_version
#define mti_mutex	mt1.mtb.mtb_mutex
#define mti_rmname	mt1.mtb.mtb_rmname
#define mti_txnid	mt1.mtb.mtb_txnid
#define mti_numreaders	mt1.mtb.mtb_numreaders
#define mti_me_toggle	mt1.mtb.mtb_me_toggle
		char pad[(sizeof(MDB_txbody)+CACHELINE-1) & ~(CACHELINE-1)];
	} mt1;
	union {
#ifdef _WIN32
		char mt2_wmname[32];
#define	mti_wmname	mt2.mt2_wmname
#else
		pthread_mutex_t	mt2_wmutex;
#define mti_wmutex	mt2.mt2_wmutex
#endif
		char pad[(sizeof(pthread_mutex_t)+CACHELINE-1) & ~(CACHELINE-1)];
	} mt2;
	MDB_reader	mti_readers[1];
} MDB_txninfo;

/* Common header for all page types. Overflow pages
 * occupy a number of contiguous pages with no
 * headers on any page after the first.
 */
typedef struct MDB_page {		/* represents a page of storage */
#define	mp_pgno		mp_p.p_pgno
	union padded {
		pgno_t		p_pgno;		/* page number */
		void *		p_align;	/* for IL32P64 */
	} mp_p;
#define	P_BRANCH	 0x01		/* branch page */
#define	P_LEAF		 0x02		/* leaf page */
#define	P_OVERFLOW	 0x04		/* overflow page */
#define	P_META		 0x08		/* meta page */
#define	P_DIRTY		 0x10		/* dirty page */
#define	P_LEAF2		 0x20		/* DB with small, fixed size keys and no data */
	uint32_t	mp_flags;
#define mp_lower	mp_pb.pb.pb_lower
#define mp_upper	mp_pb.pb.pb_upper
#define mp_pages	mp_pb.pb_pages
	union page_bounds {
		struct {
			indx_t		pb_lower;		/* lower bound of free space */
			indx_t		pb_upper;		/* upper bound of free space */
		} pb;
		uint32_t	pb_pages;	/* number of overflow pages */
	} mp_pb;
	indx_t		mp_ptrs[1];		/* dynamic size */
} MDB_page;

#define PAGEHDRSZ	 ((unsigned) offsetof(MDB_page, mp_ptrs))

#define NUMKEYS(p)	 (((p)->mp_lower - PAGEHDRSZ) >> 1)
#define SIZELEFT(p)	 (indx_t)((p)->mp_upper - (p)->mp_lower)
#define PAGEFILL(env, p) (1000L * ((env)->me_psize - PAGEHDRSZ - SIZELEFT(p)) / \
				((env)->me_psize - PAGEHDRSZ))
#define IS_LEAF(p)	 F_ISSET((p)->mp_flags, P_LEAF)
#define IS_LEAF2(p)	 F_ISSET((p)->mp_flags, P_LEAF2)
#define IS_BRANCH(p)	 F_ISSET((p)->mp_flags, P_BRANCH)
#define IS_OVERFLOW(p)	 F_ISSET((p)->mp_flags, P_OVERFLOW)

#define OVPAGES(size, psize)	((PAGEHDRSZ-1 + (size)) / (psize) + 1)

typedef struct MDB_db {
	uint32_t	md_pad;		/* also ksize for LEAF2 pages */
	uint16_t	md_flags;
	uint16_t	md_depth;
	ULONG		md_branch_pages;
	ULONG		md_leaf_pages;
	ULONG		md_overflow_pages;
	ULONG		md_entries;
	pgno_t		md_root;
} MDB_db;

#define	FREE_DBI	0
#define	MAIN_DBI	1

typedef struct MDB_meta {			/* meta (footer) page content */
	uint32_t	mm_magic;
	uint32_t	mm_version;
	void		*mm_address;		/* address for fixed mapping */
	size_t		mm_mapsize;			/* size of mmap region */
	MDB_db		mm_dbs[2];			/* first is free space, 2nd is main db */
#define	mm_psize	mm_dbs[0].md_pad
#define	mm_flags	mm_dbs[0].md_flags
	pgno_t		mm_last_pg;			/* last used page in file */
	ULONG		mm_txnid;			/* txnid that committed this page */
} MDB_meta;

typedef struct MDB_dhead {					/* a dirty page */
	MDB_page	*md_parent;
	unsigned	md_pi;				/* parent index */
	int			md_num;
} MDB_dhead;

typedef struct MDB_dpage {
	MDB_dhead	h;
	MDB_page	p;
} MDB_dpage;

typedef struct MDB_oldpages {
	struct MDB_oldpages *mo_next;
	ULONG		mo_txnid;
	pgno_t		mo_pages[1];	/* dynamic */
} MDB_oldpages;

typedef struct MDB_pageparent {
	MDB_page *mp_page;
	MDB_page *mp_parent;
	unsigned mp_pi;
} MDB_pageparent;

static MDB_dpage *mdb_alloc_page(MDB_txn *txn, MDB_dbi dbi, MDB_page *parent, unsigned int parent_idx, int num);
static int 		mdb_touch(MDB_txn *txn, MDB_dbi dbi, MDB_pageparent *mp);

typedef struct MDB_ppage {					/* ordered list of pages */
	MDB_page		*mp_page;
	unsigned int	mp_ki;		/* cursor index on page */
} MDB_ppage;

#define CURSOR_TOP(c)		 (&(c)->mc_stack[(c)->mc_snum-1])
#define CURSOR_PARENT(c)	 (&(c)->mc_stack[(c)->mc_snum-2])
#define CURSOR_STACK		 32

struct MDB_xcursor;

struct MDB_cursor {
	struct MDB_xcursor	*mc_xcursor;
	MDB_txn		*mc_txn;
	MDB_dbi		mc_dbi;
	unsigned int	mc_snum;		/* number of pushed pages */
	unsigned int	mc_flags;
#define C_INITIALIZED	0x01
#define C_EOF	0x02
#define C_XDIRTY	0x04
	MDB_ppage	mc_stack[CURSOR_STACK];		/* stack of parent pages */
};

#define METADATA(p)	 ((void *)((char *)(p) + PAGEHDRSZ))

typedef struct MDB_node {
#define mn_pgno		 mn_p.np_pgno
#define mn_dsize	 mn_p.np_dsize
	union {
		pgno_t		 np_pgno;	/* child page number */
		uint32_t	 np_dsize;	/* leaf data size */
	} mn_p;
	unsigned int	mn_flags:4;
	unsigned int	mn_ksize:12;			/* key size */
#define F_BIGDATA	 0x01			/* data put on overflow page */
#define F_SUBDATA	 0x02			/* data is a sub-database */
#define F_DUPDATA	 0x04			/* data has duplicates */
	char		mn_data[1];
} MDB_node;

typedef struct MDB_dbx {
	MDB_val		md_name;
	MDB_cmp_func	*md_cmp;		/* user compare function */
	MDB_cmp_func	*md_dcmp;		/* user dupsort function */
	MDB_rel_func	*md_rel;		/* user relocate function */
	MDB_dbi	md_parent;
	unsigned int	md_dirty;
} MDB_dbx;

struct MDB_txn {
	pgno_t		mt_next_pgno;	/* next unallocated page */
	ULONG		mt_txnid;
	MDB_env		*mt_env;	
	pgno_t		*mt_free_pgs;	/* this is an IDL */
	union {
		ID2L	dirty_list;	/* modified pages */
		MDB_reader	*reader;
	} mt_u;
	MDB_dbx		*mt_dbxs;		/* array */
	MDB_db		*mt_dbs;
	unsigned int	mt_numdbs;

#define MDB_TXN_RDONLY		0x01		/* read-only transaction */
#define MDB_TXN_ERROR		0x02		/* an error has occurred */
	unsigned int	mt_flags;
	unsigned int	mt_toggle;
};

/* Context for sorted-dup records */
typedef struct MDB_xcursor {
	MDB_cursor mx_cursor;
	MDB_txn mx_txn;
	MDB_dbx	mx_dbxs[4];
	MDB_db	mx_dbs[4];
} MDB_xcursor;

struct MDB_env {
	HANDLE		me_fd;
	HANDLE		me_lfd;
	HANDLE		me_mfd;			/* just for writing the meta pages */
#define	MDB_FATAL_ERROR	0x80000000U
	uint32_t 	me_flags;
	uint32_t	me_extrapad;	/* unused for now */
	unsigned int	me_maxreaders;
	unsigned int	me_numdbs;
	unsigned int	me_maxdbs;
	char		*me_path;
	char		*me_map;
	MDB_txninfo	*me_txns;
	MDB_meta	*me_metas[2];
	MDB_txn		*me_txn;		/* current write transaction */
	size_t		me_mapsize;
	off_t		me_size;		/* current file size */
	pgno_t		me_maxpg;		/* me_mapsize / me_psize */
	unsigned int	me_psize;
	unsigned int	me_db_toggle;
	MDB_dbx		*me_dbxs;		/* array */
	MDB_db		*me_dbs[2];
	MDB_oldpages *me_pghead;
	pthread_key_t	me_txkey;	/* thread-key for readers */
	MDB_dpage	*me_dpages;
	pgno_t		me_free_pgs[MDB_IDL_UM_SIZE];
	ID2			me_dirty_list[MDB_IDL_DB_SIZE];
	LAZY_RWLOCK_DEF(me_dblock);
#ifdef _WIN32
	HANDLE		me_rmutex;		/* Windows mutexes don't reside in shared mem */
	HANDLE		me_wmutex;
#endif
};

#define NODESIZE	 offsetof(MDB_node, mn_data)

#define INDXSIZE(k)	 (NODESIZE + ((k) == NULL ? 0 : (k)->mv_size))
#define LEAFSIZE(k, d)	 (NODESIZE + (k)->mv_size + (d)->mv_size)
#define NODEPTR(p, i)	 ((MDB_node *)((char *)(p) + (p)->mp_ptrs[i]))
#define NODEKEY(node)	 (void *)((node)->mn_data)
#define NODEDATA(node)	 (void *)((char *)(node)->mn_data + (node)->mn_ksize)
#define NODEPGNO(node)	 ((node)->mn_pgno)
#define NODEDSZ(node)	 ((node)->mn_dsize)
#define NODEKSZ(node)	 ((node)->mn_ksize)
#define LEAF2KEY(p, i, ks)	((char *)(p) + PAGEHDRSZ + ((i)*(ks)))

#define MDB_SET_KEY(node, key)	if (key!=NULL) {(key)->mv_size = NODEKSZ(node); (key)->mv_data = NODEKEY(node);}

#define MDB_COMMIT_PAGES	 64	/* max number of pages to write in one commit */

static int  mdb_search_page_root(MDB_txn *txn,
			    MDB_dbi dbi, MDB_val *key,
			    MDB_cursor *cursor, int modify,
			    MDB_pageparent *mpp);
static int  mdb_search_page(MDB_txn *txn,
			    MDB_dbi dbi, MDB_val *key,
			    MDB_cursor *cursor, int modify,
			    MDB_pageparent *mpp);

static int  mdb_env_read_header(MDB_env *env, MDB_meta *meta);
static int  mdb_env_read_meta(MDB_env *env, int *which);
static int  mdb_env_write_meta(MDB_txn *txn);
static int  mdb_get_page(MDB_txn *txn, pgno_t pgno, MDB_page **mp);

static MDB_node *mdb_search_node(MDB_txn *txn, MDB_dbi dbi, MDB_page *mp,
			    MDB_val *key, int *exactp, unsigned int *kip);
static int  mdb_add_node(MDB_txn *txn, MDB_dbi dbi, MDB_page *mp,
			    indx_t indx, MDB_val *key, MDB_val *data,
			    pgno_t pgno, uint8_t flags);
static void mdb_del_node(MDB_page *mp, indx_t indx, int ksize);
static int mdb_del0(MDB_cursor *mc, unsigned int ki,
    MDB_pageparent *mpp, MDB_node *leaf);
#if 0
static int mdb_put0(MDB_txn *txn, MDB_dbi dbi,
    MDB_val *key, MDB_val *data, unsigned int flags);
#endif
static int  mdb_read_data(MDB_txn *txn, MDB_node *leaf, MDB_val *data);

static int	mdb_rebalance(MDB_txn *txn, MDB_dbi dbi, MDB_pageparent *mp);
static int	mdb_update_key(MDB_page *mp, indx_t indx, MDB_val *key);
static int	mdb_move_node(MDB_txn *txn, MDB_dbi dbi,
				MDB_pageparent *src, indx_t srcindx,
				MDB_pageparent *dst, indx_t dstindx);
static int	mdb_merge(MDB_txn *txn, MDB_dbi dbi, MDB_pageparent *src,
			    MDB_pageparent *dst);
static int	mdb_split(MDB_txn *txn, MDB_dbi dbi, MDB_page **mpp,
			    unsigned int *newindxp, MDB_val *newkey,
			    MDB_val *newdata, pgno_t newpgno);
static MDB_dpage *mdb_new_page(MDB_txn *txn, MDB_dbi dbi, uint32_t flags, int num);

static void	cursor_pop_page(MDB_cursor *cursor);
static MDB_ppage *cursor_push_page(MDB_cursor *cursor,
			    MDB_page *mp);

static int	mdb_sibling(MDB_cursor *cursor, int move_right);
static int	mdb_cursor_next(MDB_cursor *cursor,
			    MDB_val *key, MDB_val *data, MDB_cursor_op op);
static int	mdb_cursor_prev(MDB_cursor *cursor,
			    MDB_val *key, MDB_val *data, MDB_cursor_op op);
static int	mdb_cursor_set(MDB_cursor *cursor,
			    MDB_val *key, MDB_val *data, MDB_cursor_op op, int *exactp);
static int	mdb_cursor_first(MDB_cursor *cursor,
			    MDB_val *key, MDB_val *data);
static int	mdb_cursor_last(MDB_cursor *cursor,
			    MDB_val *key, MDB_val *data);

static void	mdb_xcursor_init0(MDB_cursor *mc);
static void	mdb_xcursor_init1(MDB_cursor *mc, MDB_page *mp, MDB_node *node);
static void	mdb_xcursor_init2(MDB_cursor *mc);
static void	mdb_xcursor_fini(MDB_cursor *mc);

static size_t	mdb_leaf_size(MDB_env *env, MDB_val *key,
			    MDB_val *data);
static size_t	mdb_branch_size(MDB_env *env, MDB_val *key);

static void mdb_default_cmp(MDB_txn *txn, MDB_dbi dbi);

static MDB_cmp_func	memncmp, memnrcmp, intcmp;

#ifdef _WIN32
static SECURITY_DESCRIPTOR mdb_null_sd;
static SECURITY_ATTRIBUTES mdb_all_sa;
static int mdb_sec_inited;
#endif

char *
mdb_version(int *maj, int *min, int *pat)
{
	if (maj) *maj = MDB_VERSION_MAJOR;
	if (min) *min = MDB_VERSION_MINOR;
	if (pat) *pat = MDB_VERSION_PATCH;
	return MDB_VERSION_STRING;
}

static char *const mdb_errstr[] = {
	"MDB_KEYEXIST: Key/data pair already exists",
	"MDB_NOTFOUND: No matching key/data pair found",
	"MDB_PAGE_NOTFOUND: Requested page not found",
	"MDB_CORRUPTED: Located page was wrong type",
	"MDB_PANIC: Update of meta page failed",
	"MDB_VERSION_MISMATCH: Database environment version mismatch"
};

char *
mdb_strerror(int err)
{
	if (!err)
		return ("Successful return: 0");

	if (err >= MDB_KEYEXIST && err <= MDB_VERSION_MISMATCH)
		return mdb_errstr[err - MDB_KEYEXIST];

	return strerror(err);
}

#if DEBUG
static char *
mdb_dkey(MDB_val *key, char *buf)
{
	char *ptr = buf;
	unsigned char *c = key->mv_data;
	unsigned int i;
	if (key->mv_size > MAXKEYSIZE)
		return "MAXKEYSIZE";
#if 1
	for (i=0; i<key->mv_size; i++)
		ptr += sprintf(ptr, "%02x", *c++);
#else
	sprintf(buf, "%.*s", key->mv_size, key->mv_data);
#endif
	return buf;
}
#endif

int
mdb_cmp(MDB_txn *txn, MDB_dbi dbi, const MDB_val *a, const MDB_val *b)
{
	return txn->mt_dbxs[dbi].md_cmp(a, b);
}

int
mdb_dcmp(MDB_txn *txn, MDB_dbi dbi, const MDB_val *a, const MDB_val *b)
{
	if (txn->mt_dbxs[dbi].md_dcmp)
		return txn->mt_dbxs[dbi].md_dcmp(a, b);
	else
		return EINVAL;	/* too bad you can't distinguish this from a valid result */
}

/* Allocate new page(s) for writing */
static MDB_dpage *
mdb_alloc_page(MDB_txn *txn, MDB_dbi dbi, MDB_page *parent, unsigned int parent_idx, int num)
{
	MDB_dpage *dp;
	pgno_t pgno = P_INVALID;
	ID2 mid;

	if (txn->mt_txnid > 2) {

		if (!txn->mt_env->me_pghead && dbi != FREE_DBI &&
			txn->mt_dbs[FREE_DBI].md_root != P_INVALID) {
			/* See if there's anything in the free DB */
			MDB_cursor mc;
			MDB_pageparent mpp;
			MDB_node *leaf;
			ULONG *kptr, oldest;

			mpp.mp_parent = NULL;
			mpp.mp_pi = 0;
			mc.mc_txn = txn;
			mc.mc_dbi = FREE_DBI;
			mc.mc_snum = 0;
			mc.mc_flags = 0;
			mdb_search_page(txn, FREE_DBI, NULL, &mc, 0, &mpp);
			leaf = NODEPTR(mpp.mp_page, 0);
			kptr = (ULONG *)NODEKEY(leaf);

			{
				unsigned int i;
				oldest = txn->mt_txnid - 1;
				for (i=0; i<txn->mt_env->me_txns->mti_numreaders; i++) {
					ULONG mr = txn->mt_env->me_txns->mti_readers[i].mr_txnid;
					if (mr && mr < oldest)
						oldest = mr;
				}
			}

			if (oldest > *kptr) {
				/* It's usable, grab it.
				 */
				MDB_oldpages *mop;
				MDB_ppage *top;
				MDB_val data;
				pgno_t *idl;

				mdb_read_data(txn, leaf, &data);
				idl = (ULONG *)data.mv_data;
				mop = malloc(sizeof(MDB_oldpages) + MDB_IDL_SIZEOF(idl) - sizeof(pgno_t));
				mop->mo_next = txn->mt_env->me_pghead;
				mop->mo_txnid = *kptr;
				txn->mt_env->me_pghead = mop;
				memcpy(mop->mo_pages, idl, MDB_IDL_SIZEOF(idl));

#if DEBUG > 1
				{
					unsigned int i;
					DPRINTF("IDL read txn %lu root %lu num %lu",
						mop->mo_txnid, txn->mt_dbs[FREE_DBI].md_root, idl[0]);
					for (i=0; i<idl[0]; i++) {
						DPRINTF("IDL %lu", idl[i+1]);
					}
				}
#endif
				/* drop this IDL from the DB */
				top = CURSOR_TOP(&mc);
				top->mp_ki = 0;
				mc.mc_flags = C_INITIALIZED;
				mdb_cursor_del(&mc, 0);
			}
		}
		if (txn->mt_env->me_pghead) {
			MDB_oldpages *mop = txn->mt_env->me_pghead;
			if (num > 1) {
				/* FIXME: For now, always use fresh pages. We
				 * really ought to search the free list for a
				 * contiguous range.
				 */
				;
			} else {
				/* peel pages off tail, so we only have to truncate the list */
				pgno = MDB_IDL_LAST(mop->mo_pages);
				if (MDB_IDL_IS_RANGE(mop->mo_pages)) {
					mop->mo_pages[2]++;
					if (mop->mo_pages[2] > mop->mo_pages[1])
						mop->mo_pages[0] = 0;
				} else {
					mop->mo_pages[0]--;
				}
				if (MDB_IDL_IS_ZERO(mop->mo_pages)) {
					txn->mt_env->me_pghead = mop->mo_next;
					free(mop);
				}
			}
		}
	}

	if (pgno == P_INVALID) {
		/* DB size is maxed out */
		if (txn->mt_next_pgno + num >= txn->mt_env->me_maxpg)
			return NULL;
	}
	if (txn->mt_env->me_dpages && num == 1) {
		dp = txn->mt_env->me_dpages;
		txn->mt_env->me_dpages = (MDB_dpage *)dp->h.md_parent;
	} else {
		if ((dp = malloc(txn->mt_env->me_psize * num + sizeof(MDB_dhead))) == NULL)
			return NULL;
	}
	dp->h.md_num = num;
	dp->h.md_parent = parent;
	dp->h.md_pi = parent_idx;
	if (pgno == P_INVALID) {
		dp->p.mp_pgno = txn->mt_next_pgno;
		txn->mt_next_pgno += num;
	} else {
		dp->p.mp_pgno = pgno;
	}
	mid.mid = dp->p.mp_pgno;
	mid.mptr = dp;
	mdb_mid2l_insert(txn->mt_u.dirty_list, &mid);

	return dp;
}

/* Touch a page: make it dirty and re-insert into tree with updated pgno.
 */
static int
mdb_touch(MDB_txn *txn, MDB_dbi dbi, MDB_pageparent *pp)
{
	MDB_page *mp = pp->mp_page;
	pgno_t	pgno;
	assert(txn != NULL);
	assert(pp != NULL);

	if (!F_ISSET(mp->mp_flags, P_DIRTY)) {
		MDB_dpage *dp;
		if ((dp = mdb_alloc_page(txn, dbi, pp->mp_parent, pp->mp_pi, 1)) == NULL)
			return ENOMEM;
		DPRINTF("touched db %u page %lu -> %lu", dbi, mp->mp_pgno, dp->p.mp_pgno);
		assert(mp->mp_pgno != dp->p.mp_pgno);
		mdb_midl_append(txn->mt_free_pgs, mp->mp_pgno);
		pgno = dp->p.mp_pgno;
		memcpy(&dp->p, mp, txn->mt_env->me_psize);
		mp = &dp->p;
		mp->mp_pgno = pgno;
		mp->mp_flags |= P_DIRTY;

		/* Update the page number to new touched page. */
		if (pp->mp_parent != NULL)
			NODEPGNO(NODEPTR(pp->mp_parent, pp->mp_pi)) = mp->mp_pgno;
		pp->mp_page = mp;
	}
	return 0;
}

int
mdb_env_sync(MDB_env *env, int force)
{
	int rc = 0;
	if (force || !F_ISSET(env->me_flags, MDB_NOSYNC)) {
		if (fdatasync(env->me_fd))
			rc = ErrCode();
	}
	return rc;
}

static inline void
mdb_txn_reset0(MDB_txn *txn);

static inline int
mdb_txn_renew0(MDB_txn *txn)
{
	MDB_env *env = txn->mt_env;

	if (txn->mt_flags & MDB_TXN_RDONLY) {
		MDB_reader *r = pthread_getspecific(env->me_txkey);
		if (!r) {
			unsigned int i;
			pid_t pid = getpid();
			pthread_t tid = pthread_self();

			LOCK_MUTEX_R(env);
			for (i=0; i<env->me_txns->mti_numreaders; i++)
				if (env->me_txns->mti_readers[i].mr_pid == 0)
					break;
			if (i == env->me_maxreaders) {
				UNLOCK_MUTEX_R(env);
				return ENOMEM;
			}
			env->me_txns->mti_readers[i].mr_pid = pid;
			env->me_txns->mti_readers[i].mr_tid = tid;
			if (i >= env->me_txns->mti_numreaders)
				env->me_txns->mti_numreaders = i+1;
			UNLOCK_MUTEX_R(env);
			r = &env->me_txns->mti_readers[i];
			pthread_setspecific(env->me_txkey, r);
		}
		txn->mt_txnid = env->me_txns->mti_txnid;
		txn->mt_toggle = env->me_txns->mti_me_toggle;
		r->mr_txnid = txn->mt_txnid;
		txn->mt_u.reader = r;
	} else {
		LOCK_MUTEX_W(env);

		txn->mt_txnid = env->me_txns->mti_txnid+1;
		txn->mt_toggle = env->me_txns->mti_me_toggle;
		txn->mt_u.dirty_list = env->me_dirty_list;
		txn->mt_u.dirty_list[0].mid = 0;
		txn->mt_free_pgs = env->me_free_pgs;
		txn->mt_free_pgs[0] = 0;
		txn->mt_next_pgno = env->me_metas[txn->mt_toggle]->mm_last_pg+1;
		env->me_txn = txn;
	}

	/* Copy the DB arrays */
	LAZY_RWLOCK_RDLOCK(&env->me_dblock);
	txn->mt_numdbs = env->me_numdbs;
	txn->mt_dbxs = env->me_dbxs;	/* mostly static anyway */
	memcpy(txn->mt_dbs, env->me_metas[txn->mt_toggle]->mm_dbs, 2 * sizeof(MDB_db));
	if (txn->mt_numdbs > 2)
		memcpy(txn->mt_dbs+2, env->me_dbs[env->me_db_toggle]+2,
			(txn->mt_numdbs - 2) * sizeof(MDB_db));
	LAZY_RWLOCK_UNLOCK(&env->me_dblock);

	return MDB_SUCCESS;
}

int
mdb_txn_renew(MDB_txn *txn)
{
	int rc;

	if (!txn)
		return EINVAL;

	if (txn->mt_env->me_flags & MDB_FATAL_ERROR) {
		DPUTS("environment had fatal error, must shutdown!");
		return MDB_PANIC;
	}

	rc = mdb_txn_renew0(txn);
	if (rc == MDB_SUCCESS) {
		DPRINTF("renew txn %lu%c %p on mdbenv %p, root page %lu",
			txn->mt_txnid, (txn->mt_flags & MDB_TXN_RDONLY) ? 'r' : 'w', txn,
			(void *)txn->mt_env, txn->mt_dbs[MAIN_DBI].md_root);
	}
	return rc;
}

int
mdb_txn_begin(MDB_env *env, unsigned int flags, MDB_txn **ret)
{
	MDB_txn *txn;
	int rc;

	if (env->me_flags & MDB_FATAL_ERROR) {
		DPUTS("environment had fatal error, must shutdown!");
		return MDB_PANIC;
	}
	if ((txn = calloc(1, sizeof(MDB_txn) + env->me_maxdbs * sizeof(MDB_db))) == NULL) {
		DPRINTF("calloc: %s", strerror(ErrCode()));
		return ENOMEM;
	}
	txn->mt_dbs = (MDB_db *)(txn+1);
	if (flags & MDB_RDONLY) {
		txn->mt_flags |= MDB_TXN_RDONLY;
	}
	txn->mt_env = env;

	rc = mdb_txn_renew0(txn);
	if (rc)
		free(txn);
	else {
		*ret = txn;
		DPRINTF("begin txn %lu%c %p on mdbenv %p, root page %lu",
			txn->mt_txnid, (txn->mt_flags & MDB_TXN_RDONLY) ? 'r' : 'w', txn,
			(void *) env, txn->mt_dbs[MAIN_DBI].md_root);
	}

	return rc;
}

static inline void
mdb_txn_reset0(MDB_txn *txn)
{
	MDB_env	*env = txn->mt_env;

	if (F_ISSET(txn->mt_flags, MDB_TXN_RDONLY)) {
		txn->mt_u.reader->mr_txnid = 0;
	} else {
		MDB_oldpages *mop;
		MDB_dpage *dp;
		unsigned int i;

		/* return all dirty pages to dpage list */
		for (i=1; i<=txn->mt_u.dirty_list[0].mid; i++) {
			dp = txn->mt_u.dirty_list[i].mptr;
			if (dp->h.md_num == 1) {
				dp->h.md_parent = (MDB_page *)txn->mt_env->me_dpages;
				txn->mt_env->me_dpages = dp;
			} else {
				/* large pages just get freed directly */
				free(dp);
			}
		}

		while ((mop = txn->mt_env->me_pghead)) {
			txn->mt_env->me_pghead = mop->mo_next;
			free(mop);
		}

		env->me_txn = NULL;
		for (i=2; i<env->me_numdbs; i++)
			env->me_dbxs[i].md_dirty = 0;
		UNLOCK_MUTEX_W(env);
	}
}

void
mdb_txn_reset(MDB_txn *txn)
{
	if (txn == NULL)
		return;

	DPRINTF("reset txn %lu%c %p on mdbenv %p, root page %lu",
		txn->mt_txnid, (txn->mt_flags & MDB_TXN_RDONLY) ? 'r' : 'w', txn,
		(void *)txn->mt_env, txn->mt_dbs[MAIN_DBI].md_root);

	mdb_txn_reset0(txn);
}

void
mdb_txn_abort(MDB_txn *txn)
{
	if (txn == NULL)
		return;

	DPRINTF("abort txn %lu%c %p on mdbenv %p, root page %lu",
		txn->mt_txnid, (txn->mt_flags & MDB_TXN_RDONLY) ? 'r' : 'w', txn,
		(void *)txn->mt_env, txn->mt_dbs[MAIN_DBI].md_root);

	mdb_txn_reset0(txn);
	free(txn);
}

int
mdb_txn_commit(MDB_txn *txn)
{
	int		 n, done;
	unsigned int i;
	ssize_t		 rc;
	off_t		 size;
	MDB_dpage	*dp;
	MDB_env	*env;
	pgno_t	next;
	MDB_cursor mc;

	assert(txn != NULL);
	assert(txn->mt_env != NULL);

	env = txn->mt_env;

	if (F_ISSET(txn->mt_flags, MDB_TXN_RDONLY)) {
		mdb_txn_abort(txn);
		return MDB_SUCCESS;
	}

	if (txn != env->me_txn) {
		DPUTS("attempt to commit unknown transaction");
		mdb_txn_abort(txn);
		return EINVAL;
	}

	if (F_ISSET(txn->mt_flags, MDB_TXN_ERROR)) {
		DPUTS("error flag is set, can't commit");
		mdb_txn_abort(txn);
		return EINVAL;
	}

	if (!txn->mt_u.dirty_list[0].mid)
		goto done;

	DPRINTF("committing txn %lu %p on mdbenv %p, root page %lu",
	    txn->mt_txnid, txn, (void *)env, txn->mt_dbs[MAIN_DBI].md_root);

	mc.mc_txn = txn;
	mc.mc_dbi = FREE_DBI;
	mc.mc_flags = 0;

	/* should only be one record now */
	if (env->me_pghead) {
		MDB_pageparent mpp;

		/* make sure first page of freeDB is touched and on freelist */
		mpp.mp_parent = NULL;
		mpp.mp_pi = 0;
		mc.mc_snum = 0;
		mdb_search_page(txn, FREE_DBI, NULL, &mc, 1, &mpp);
	}
	/* save to free list */
	if (!MDB_IDL_IS_ZERO(txn->mt_free_pgs)) {
		MDB_val key, data;
		MDB_pageparent mpp;
		ULONG i;

		/* make sure last page of freeDB is touched and on freelist */
		key.mv_size = MAXKEYSIZE+1;
		key.mv_data = NULL;
		mpp.mp_parent = NULL;
		mpp.mp_pi = 0;
		mc.mc_snum = 0;
		mdb_search_page(txn, FREE_DBI, &key, &mc, 1, &mpp);

		mdb_midl_sort(txn->mt_free_pgs);
#if DEBUG > 1
		{
			unsigned int i;
			ULONG *idl = txn->mt_free_pgs;
			DPRINTF("IDL write txn %lu root %lu num %lu",
				txn->mt_txnid, txn->mt_dbs[FREE_DBI].md_root, idl[0]);
			for (i=0; i<idl[0]; i++) {
				DPRINTF("IDL %lu", idl[i+1]);
			}
		}
#endif
		/* write to last page of freeDB */
		key.mv_size = sizeof(pgno_t);
		key.mv_data = (char *)&txn->mt_txnid;
		data.mv_data = txn->mt_free_pgs;
		/* The free list can still grow during this call,
		 * despite the pre-emptive touches above. So check
		 * and make sure the entire thing got written.
		 */
		do {
			i = txn->mt_free_pgs[0];
			data.mv_size = MDB_IDL_SIZEOF(txn->mt_free_pgs);
			rc = mdb_cursor_put(&mc, &key, &data, 0);
			if (rc) {
				mdb_txn_abort(txn);
				return rc;
			}
		} while (i != txn->mt_free_pgs[0]);
	}
	/* should only be one record now */
	if (env->me_pghead) {
		MDB_val key, data;
		MDB_oldpages *mop;

		mop = env->me_pghead;
		key.mv_size = sizeof(pgno_t);
		key.mv_data = (char *)&mop->mo_txnid;
		data.mv_size = MDB_IDL_SIZEOF(mop->mo_pages);
		data.mv_data = mop->mo_pages;
		mdb_cursor_put(&mc, &key, &data, 0);
		free(env->me_pghead);
		env->me_pghead = NULL;
	}

	/* Update DB root pointers. Their pages have already been
	 * touched so this is all in-place and cannot fail.
	 */
	{
		MDB_val data;
		data.mv_size = sizeof(MDB_db);

		mc.mc_dbi = MAIN_DBI;
		mc.mc_flags = 0;
		for (i = 2; i < txn->mt_numdbs; i++) {
			if (txn->mt_dbxs[i].md_dirty) {
				data.mv_data = &txn->mt_dbs[i];
				mdb_cursor_put(&mc, &txn->mt_dbxs[i].md_name, &data, 0);
			}
		}
	}

	/* Commit up to MDB_COMMIT_PAGES dirty pages to disk until done.
	 */
	next = 0;
	i = 1;
	do {
#ifdef _WIN32
		/* Windows actually supports scatter/gather I/O, but only on
		 * unbuffered file handles. Since we're relying on the OS page
		 * cache for all our data, that's self-defeating. So we just
		 * write pages one at a time. We use the ov structure to set
		 * the write offset, to at least save the overhead of a Seek
		 * system call.
		 */
		OVERLAPPED ov;
		memset(&ov, 0, sizeof(ov));
		for (; i<=txn->mt_u.dirty_list[0].mid; i++) {
			dp = txn->mt_u.dirty_list[i].mptr;
			DPRINTF("committing page %lu", dp->p.mp_pgno);
			size = dp->p.mp_pgno * env->me_psize;
			ov.Offset = size & 0xffffffff;
			ov.OffsetHigh = size >> 16;
			ov.OffsetHigh >>= 16;
			/* clear dirty flag */
			dp->p.mp_flags &= ~P_DIRTY;
			rc = WriteFile(env->me_fd, &dp->p, env->me_psize * dp->h.md_num, NULL, &ov);
			if (!rc) {
				n = ErrCode();
				DPRINTF("WriteFile: %d", n);
				mdb_txn_abort(txn);
				return n;
			}
		}
		done = 1;;
#else
		struct iovec	 iov[MDB_COMMIT_PAGES];
		n = 0;
		done = 1;
		size = 0;
		for (; i<=txn->mt_u.dirty_list[0].mid; i++) {
			dp = txn->mt_u.dirty_list[i].mptr;
			if (dp->p.mp_pgno != next) {
				if (n) {
					DPRINTF("committing %u dirty pages", n);
					rc = writev(env->me_fd, iov, n);
					if (rc != size) {
						n = ErrCode();
						if (rc > 0)
							DPUTS("short write, filesystem full?");
						else
							DPRINTF("writev: %s", strerror(n));
						mdb_txn_abort(txn);
						return n;
					}
					n = 0;
					size = 0;
				}
				lseek(env->me_fd, dp->p.mp_pgno * env->me_psize, SEEK_SET);
				next = dp->p.mp_pgno;
			}
			DPRINTF("committing page %lu", dp->p.mp_pgno);
			iov[n].iov_len = env->me_psize * dp->h.md_num;
			iov[n].iov_base = &dp->p;
			size += iov[n].iov_len;
			next = dp->p.mp_pgno + dp->h.md_num;
			/* clear dirty flag */
			dp->p.mp_flags &= ~P_DIRTY;
			if (++n >= MDB_COMMIT_PAGES) {
				done = 0;
				i++;
				break;
			}
		}

		if (n == 0)
			break;

		DPRINTF("committing %u dirty pages", n);
		rc = writev(env->me_fd, iov, n);
		if (rc != size) {
			n = ErrCode();
			if (rc > 0)
				DPUTS("short write, filesystem full?");
			else
				DPRINTF("writev: %s", strerror(n));
			mdb_txn_abort(txn);
			return n;
		}
#endif
	} while (!done);

	/* Drop the dirty pages.
	 */
	for (i=1; i<=txn->mt_u.dirty_list[0].mid; i++) {
		dp = txn->mt_u.dirty_list[i].mptr;
		if (dp->h.md_num == 1) {
			dp->h.md_parent = (MDB_page *)txn->mt_env->me_dpages;
			txn->mt_env->me_dpages = dp;
		} else {
			free(dp);
		}
		txn->mt_u.dirty_list[i].mid = 0;
	}
	txn->mt_u.dirty_list[0].mid = 0;

	if ((n = mdb_env_sync(env, 0)) != 0 ||
	    (n = mdb_env_write_meta(txn)) != MDB_SUCCESS) {
		mdb_txn_abort(txn);
		return n;
	}

done:
	env->me_txn = NULL;
	/* update the DB tables */
	{
		int toggle = !env->me_db_toggle;
		MDB_db *ip, *jp;

		ip = &env->me_dbs[toggle][2];
		jp = &txn->mt_dbs[2];
		LAZY_RWLOCK_WRLOCK(&env->me_dblock);
		for (i = 2; i < txn->mt_numdbs; i++) {
			if (ip->md_root != jp->md_root)
				*ip = *jp;
			ip++; jp++;
		}

		for (i = 2; i < txn->mt_numdbs; i++) {
			if (txn->mt_dbxs[i].md_dirty)
				txn->mt_dbxs[i].md_dirty = 0;
		}
		env->me_db_toggle = toggle;
		env->me_numdbs = txn->mt_numdbs;
		LAZY_RWLOCK_UNLOCK(&env->me_dblock);
	}

	UNLOCK_MUTEX_W(env);
	free(txn);

	return MDB_SUCCESS;
}

static int
mdb_env_read_header(MDB_env *env, MDB_meta *meta)
{
	char		 page[PAGESIZE];
	MDB_page	*p;
	MDB_meta	*m;
	int		 rc, err;

	/* We don't know the page size yet, so use a minimum value.
	 */

#ifdef _WIN32
	if (!ReadFile(env->me_fd, page, PAGESIZE, (DWORD *)&rc, NULL) || rc == 0)
#else
	if ((rc = read(env->me_fd, page, PAGESIZE)) == 0)
#endif
	{
		return ENOENT;
	}
	else if (rc != PAGESIZE) {
		err = ErrCode();
		if (rc > 0)
			err = EINVAL;
		DPRINTF("read: %s", strerror(err));
		return err;
	}

	p = (MDB_page *)page;

	if (!F_ISSET(p->mp_flags, P_META)) {
		DPRINTF("page %lu not a meta page", p->mp_pgno);
		return EINVAL;
	}

	m = METADATA(p);
	if (m->mm_magic != MDB_MAGIC) {
		DPUTS("meta has invalid magic");
		return EINVAL;
	}

	if (m->mm_version != MDB_VERSION) {
		DPRINTF("database is version %u, expected version %u",
		    m->mm_version, MDB_VERSION);
		return MDB_VERSION_MISMATCH;
	}

	memcpy(meta, m, sizeof(*m));
	return 0;
}

static int
mdb_env_init_meta(MDB_env *env, MDB_meta *meta)
{
	MDB_page *p, *q;
	MDB_meta *m;
	int rc;
	unsigned int	 psize;

	DPUTS("writing new meta page");

	GetPageSize(psize);

	meta->mm_magic = MDB_MAGIC;
	meta->mm_version = MDB_VERSION;
	meta->mm_psize = psize;
	meta->mm_last_pg = 1;
	meta->mm_flags = env->me_flags & 0xffff;
	meta->mm_flags |= MDB_INTEGERKEY;
	meta->mm_dbs[0].md_root = P_INVALID;
	meta->mm_dbs[1].md_root = P_INVALID;

	p = calloc(2, psize);
	p->mp_pgno = 0;
	p->mp_flags = P_META;

	m = METADATA(p);
	memcpy(m, meta, sizeof(*meta));

	q = (MDB_page *)((char *)p + psize);

	q->mp_pgno = 1;
	q->mp_flags = P_META;

	m = METADATA(q);
	memcpy(m, meta, sizeof(*meta));

#ifdef _WIN32
	{
		DWORD len;
		rc = WriteFile(env->me_fd, p, psize * 2, &len, NULL);
		rc = (len == psize * 2) ? MDB_SUCCESS : ErrCode();
	}
#else
	rc = write(env->me_fd, p, psize * 2);
	rc = (rc == (int)psize * 2) ? MDB_SUCCESS : ErrCode();
#endif
	free(p);
	return rc;
}

static int
mdb_env_write_meta(MDB_txn *txn)
{
	MDB_env *env;
	MDB_meta	meta, metab;
	off_t off;
	int rc, len, toggle;
	char *ptr;
#ifdef _WIN32
	OVERLAPPED ov;
#endif

	assert(txn != NULL);
	assert(txn->mt_env != NULL);

	toggle = !txn->mt_toggle;
	DPRINTF("writing meta page %d for root page %lu",
		toggle, txn->mt_dbs[MAIN_DBI].md_root);

	env = txn->mt_env;

	metab.mm_txnid = env->me_metas[toggle]->mm_txnid;
	metab.mm_last_pg = env->me_metas[toggle]->mm_last_pg;

	ptr = (char *)&meta;
	off = offsetof(MDB_meta, mm_dbs[0].md_depth);
	len = sizeof(MDB_meta) - off;

	ptr += off;
	meta.mm_dbs[0] = txn->mt_dbs[0];
	meta.mm_dbs[1] = txn->mt_dbs[1];
	meta.mm_last_pg = txn->mt_next_pgno - 1;
	meta.mm_txnid = txn->mt_txnid;

	if (toggle)
		off += env->me_psize;
	off += PAGEHDRSZ;

	/* Write to the SYNC fd */
#ifdef _WIN32
	{
		memset(&ov, 0, sizeof(ov));
		ov.Offset = off;
		WriteFile(env->me_mfd, ptr, len, (DWORD *)&rc, &ov);
	}
#else
	rc = pwrite(env->me_mfd, ptr, len, off);
#endif
	if (rc != len) {
		int r2;
		rc = ErrCode();
		DPUTS("write failed, disk error?");
		/* On a failure, the pagecache still contains the new data.
		 * Write some old data back, to prevent it from being used.
		 * Use the non-SYNC fd; we know it will fail anyway.
		 */
		meta.mm_last_pg = metab.mm_last_pg;
		meta.mm_txnid = metab.mm_txnid;
#ifdef _WIN32
		WriteFile(env->me_fd, ptr, len, NULL, &ov);
#else
		r2 = pwrite(env->me_fd, ptr, len, off);
#endif
		env->me_flags |= MDB_FATAL_ERROR;
		return rc;
	}
	/* Memory ordering issues are irrelevant; since the entire writer
	 * is wrapped by wmutex, all of these changes will become visible
	 * after the wmutex is unlocked. Since the DB is multi-version,
	 * readers will get consistent data regardless of how fresh or
	 * how stale their view of these values is.
	 */
	LAZY_MUTEX_LOCK(&env->me_txns->mti_mutex);
	txn->mt_env->me_txns->mti_me_toggle = toggle;
	txn->mt_env->me_txns->mti_txnid = txn->mt_txnid;
	LAZY_MUTEX_UNLOCK(&env->me_txns->mti_mutex);

	return MDB_SUCCESS;
}

static int
mdb_env_read_meta(MDB_env *env, int *which)
{
	int toggle = 0;

	assert(env != NULL);

	if (env->me_metas[0]->mm_txnid < env->me_metas[1]->mm_txnid)
		toggle = 1;

	DPRINTF("Using meta page %d", toggle);
	*which = toggle;

	return MDB_SUCCESS;
}

int
mdb_env_create(MDB_env **env)
{
	MDB_env *e;

	e = calloc(1, sizeof(MDB_env));
	if (!e) return ENOMEM;

	e->me_maxreaders = DEFAULT_READERS;
	e->me_maxdbs = 2;
	e->me_fd = INVALID_HANDLE_VALUE;
	e->me_lfd = INVALID_HANDLE_VALUE;
	e->me_mfd = INVALID_HANDLE_VALUE;
	*env = e;
	return MDB_SUCCESS;
}

int
mdb_env_set_mapsize(MDB_env *env, size_t size)
{
	if (env->me_map)
		return EINVAL;
	env->me_mapsize = size;
	return MDB_SUCCESS;
}

int
mdb_env_set_maxdbs(MDB_env *env, int dbs)
{
	if (env->me_map)
		return EINVAL;
	env->me_maxdbs = dbs;
	return MDB_SUCCESS;
}

int
mdb_env_set_maxreaders(MDB_env *env, int readers)
{
	if (env->me_map)
		return EINVAL;
	env->me_maxreaders = readers;
	return MDB_SUCCESS;
}

int
mdb_env_get_maxreaders(MDB_env *env, int *readers)
{
	if (!env || !readers)
		return EINVAL;
	*readers = env->me_maxreaders;
	return MDB_SUCCESS;
}

static int
mdb_env_open2(MDB_env *env, unsigned int flags)
{
	int i, newenv = 0, toggle;
	MDB_meta meta;
	MDB_page *p;

	env->me_flags = flags;

	memset(&meta, 0, sizeof(meta));

	if ((i = mdb_env_read_header(env, &meta)) != 0) {
		if (i != ENOENT)
			return i;
		DPUTS("new mdbenv");
		newenv = 1;
	}

	if (!env->me_mapsize) {
		env->me_mapsize = newenv ? DEFAULT_MAPSIZE : meta.mm_mapsize;
	}

#ifdef _WIN32
	{
		HANDLE mh;
		LONG sizelo, sizehi;
		sizelo = env->me_mapsize & 0xffffffff;
		sizehi = env->me_mapsize >> 16;		/* pointless on WIN32, only needed on W64 */
		sizehi >>= 16;
		/* Windows won't create mappings for zero length files.
		 * Just allocate the maxsize right now.
		 */
		if (newenv) {
			SetFilePointer(env->me_fd, sizelo, sizehi ? &sizehi : NULL, 0);
			if (!SetEndOfFile(env->me_fd))
				return ErrCode();
			SetFilePointer(env->me_fd, 0, NULL, 0);
		}
		mh = CreateFileMapping(env->me_fd, NULL, PAGE_READONLY,
			sizehi, sizelo, NULL);
		if (!mh)
			return ErrCode();
		env->me_map = MapViewOfFileEx(mh, FILE_MAP_READ, 0, 0, env->me_mapsize,
			meta.mm_address);
		CloseHandle(mh);
		if (!env->me_map)
			return ErrCode();
	}
#else
	i = MAP_SHARED;
	if (meta.mm_address && (flags & MDB_FIXEDMAP))
		i |= MAP_FIXED;
	env->me_map = mmap(meta.mm_address, env->me_mapsize, PROT_READ, i,
		env->me_fd, 0);
	if (env->me_map == MAP_FAILED)
		return ErrCode();
#endif

	if (newenv) {
		meta.mm_mapsize = env->me_mapsize;
		if (flags & MDB_FIXEDMAP)
			meta.mm_address = env->me_map;
		i = mdb_env_init_meta(env, &meta);
		if (i != MDB_SUCCESS) {
			munmap(env->me_map, env->me_mapsize);
			return i;
		}
	}
	env->me_psize = meta.mm_psize;

	env->me_maxpg = env->me_mapsize / env->me_psize;

	p = (MDB_page *)env->me_map;
	env->me_metas[0] = METADATA(p);
	env->me_metas[1] = (MDB_meta *)((char *)env->me_metas[0] + meta.mm_psize);

	if ((i = mdb_env_read_meta(env, &toggle)) != 0)
		return i;

	DPRINTF("opened database version %u, pagesize %u",
	    env->me_metas[toggle]->mm_version, env->me_psize);
	DPRINTF("depth: %u", env->me_metas[toggle]->mm_dbs[MAIN_DBI].md_depth);
	DPRINTF("entries: %lu", env->me_metas[toggle]->mm_dbs[MAIN_DBI].md_entries);
	DPRINTF("branch pages: %lu", env->me_metas[toggle]->mm_dbs[MAIN_DBI].md_branch_pages);
	DPRINTF("leaf pages: %lu", env->me_metas[toggle]->mm_dbs[MAIN_DBI].md_leaf_pages);
	DPRINTF("overflow pages: %lu", env->me_metas[toggle]->mm_dbs[MAIN_DBI].md_overflow_pages);
	DPRINTF("root: %lu", env->me_metas[toggle]->mm_dbs[MAIN_DBI].md_root);

	return MDB_SUCCESS;
}

#ifndef _WIN32
/* Windows doesn't support destructor callbacks for thread-specific storage */
static void
mdb_env_reader_dest(void *ptr)
{
	MDB_reader *reader = ptr;

	reader->mr_txnid = 0;
	reader->mr_pid = 0;
	reader->mr_tid = 0;
}
#endif

/* downgrade the exclusive lock on the region back to shared */
static void
mdb_env_share_locks(MDB_env *env)
{
	int toggle = 0;

	if (env->me_metas[0]->mm_txnid < env->me_metas[1]->mm_txnid)
		toggle = 1;
	env->me_txns->mti_me_toggle = toggle;
	env->me_txns->mti_txnid = env->me_metas[toggle]->mm_txnid;

#ifdef _WIN32
	{
		OVERLAPPED ov;
		/* First acquire a shared lock. The Unlock will
		 * then release the existing exclusive lock.
		 */
		memset(&ov, 0, sizeof(ov));
		LockFileEx(env->me_lfd, 0, 0, 1, 0, &ov);
		UnlockFile(env->me_lfd, 0, 0, 1, 0);
	}
#else
	{
		struct flock lock_info;
		/* The shared lock replaces the existing lock */
		memset((void *)&lock_info, 0, sizeof(lock_info));
		lock_info.l_type = F_RDLCK;
		lock_info.l_whence = SEEK_SET;
		lock_info.l_start = 0;
		lock_info.l_len = 1;
		fcntl(env->me_lfd, F_SETLK, &lock_info);
	}
#endif
}

static int
mdb_env_setup_locks(MDB_env *env, char *lpath, int mode, int *excl)
{
	int rc;
	off_t size, rsize;

	*excl = 0;

#ifdef _WIN32
	if ((env->me_lfd = CreateFile(lpath, GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		rc = ErrCode();
		return rc;
	}
	/* Try to get exclusive lock. If we succeed, then
	 * nobody is using the lock region and we should initialize it.
	 */
	{
		if (LockFile(env->me_lfd, 0, 0, 1, 0)) {
			*excl = 1;
		} else {
			OVERLAPPED ov;
			memset(&ov, 0, sizeof(ov));
			if (!LockFileEx(env->me_lfd, 0, 0, 1, 0, &ov)) {
				rc = ErrCode();
				goto fail;
			}
		}
	}
	size = GetFileSize(env->me_lfd, NULL);
#else
	if ((env->me_lfd = open(lpath, O_RDWR|O_CREAT, mode)) == -1) {
		rc = ErrCode();
		return rc;
	}
	/* Try to get exclusive lock. If we succeed, then
	 * nobody is using the lock region and we should initialize it.
	 */
	{
		struct flock lock_info;
		memset((void *)&lock_info, 0, sizeof(lock_info));
		lock_info.l_type = F_WRLCK;
		lock_info.l_whence = SEEK_SET;
		lock_info.l_start = 0;
		lock_info.l_len = 1;
		rc = fcntl(env->me_lfd, F_SETLK, &lock_info);
		if (rc == 0) {
			*excl = 1;
		} else {
			lock_info.l_type = F_RDLCK;
			rc = fcntl(env->me_lfd, F_SETLKW, &lock_info);
			if (rc) {
				rc = ErrCode();
				goto fail;
			}
		}
	}
	size = lseek(env->me_lfd, 0, SEEK_END);
#endif
	rsize = (env->me_maxreaders-1) * sizeof(MDB_reader) + sizeof(MDB_txninfo);
	if (size < rsize && *excl) {
#ifdef _WIN32
		SetFilePointer(env->me_lfd, rsize, NULL, 0);
		if (!SetEndOfFile(env->me_lfd)) {
			rc = ErrCode();
			goto fail;
		}
#else
		if (ftruncate(env->me_lfd, rsize) != 0) {
			rc = ErrCode();
			goto fail;
		}
#endif
	} else {
		rsize = size;
		size = rsize - sizeof(MDB_txninfo);
		env->me_maxreaders = size/sizeof(MDB_reader) + 1;
	}
#ifdef _WIN32
	{
		HANDLE mh;
		mh = CreateFileMapping(env->me_lfd, NULL, PAGE_READWRITE,
			0, 0, NULL);
		if (!mh) {
			rc = ErrCode();
			goto fail;
		}
		env->me_txns = MapViewOfFileEx(mh, FILE_MAP_WRITE, 0, 0, rsize, NULL);
		CloseHandle(mh);
		if (!env->me_txns) {
			rc = ErrCode();
			goto fail;
		}
	}
#else
	env->me_txns = mmap(0, rsize, PROT_READ|PROT_WRITE, MAP_SHARED,
		env->me_lfd, 0);
	if (env->me_txns == MAP_FAILED) {
		rc = ErrCode();
		goto fail;
	}
#endif
	if (*excl) {
#ifdef _WIN32
		char *ptr;
		if (!mdb_sec_inited) {
			InitializeSecurityDescriptor(&mdb_null_sd,
				SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&mdb_null_sd, TRUE, 0, FALSE);
			mdb_all_sa.nLength = sizeof(SECURITY_ATTRIBUTES);
			mdb_all_sa.bInheritHandle = FALSE;
			mdb_all_sa.lpSecurityDescriptor = &mdb_null_sd;
			mdb_sec_inited = 1;
		}
		/* FIXME: only using up to 20 characters of the env path here,
		 * probably not enough to assure uniqueness...
		 */
		sprintf(env->me_txns->mti_rmname, "Global\\MDBr%.20s", lpath);
		ptr = env->me_txns->mti_rmname + sizeof("Global\\MDBr");
		while ((ptr = strchr(ptr, '\\')))
			*ptr++ = '/';
		env->me_rmutex = CreateMutex(&mdb_all_sa, FALSE, env->me_txns->mti_rmname);
		if (!env->me_rmutex) {
			rc = ErrCode();
			goto fail;
		}
		sprintf(env->me_txns->mti_rmname, "Global\\MDBw%.20s", lpath);
		ptr = env->me_txns->mti_rmname + sizeof("Global\\MDBw");
		while ((ptr = strchr(ptr, '\\')))
			*ptr++ = '/';
		env->me_wmutex = CreateMutex(&mdb_all_sa, FALSE, env->me_txns->mti_rmname);
		if (!env->me_wmutex) {
			rc = ErrCode();
			goto fail;
		}
#else
		pthread_mutexattr_t mattr;

		pthread_mutexattr_init(&mattr);
		rc = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
		if (rc) {
			goto fail;
		}
		pthread_mutex_init(&env->me_txns->mti_mutex, &mattr);
		pthread_mutex_init(&env->me_txns->mti_wmutex, &mattr);
#endif
		env->me_txns->mti_version = MDB_VERSION;
		env->me_txns->mti_magic = MDB_MAGIC;
		env->me_txns->mti_txnid = 0;
		env->me_txns->mti_numreaders = 0;
		env->me_txns->mti_me_toggle = 0;

	} else {
		if (env->me_txns->mti_magic != MDB_MAGIC) {
			DPUTS("lock region has invalid magic");
			rc = EINVAL;
			goto fail;
		}
		if (env->me_txns->mti_version != MDB_VERSION) {
			DPRINTF("lock region is version %u, expected version %u",
				env->me_txns->mti_version, MDB_VERSION);
			rc = MDB_VERSION_MISMATCH;
			goto fail;
		}
		rc = ErrCode();
		if (rc != EACCES && rc != EAGAIN) {
			goto fail;
		}
#ifdef _WIN32
		env->me_rmutex = OpenMutex(SYNCHRONIZE, FALSE, env->me_txns->mti_rmname);
		if (!env->me_rmutex) {
			rc = ErrCode();
			goto fail;
		}
		env->me_wmutex = OpenMutex(SYNCHRONIZE, FALSE, env->me_txns->mti_wmname);
		if (!env->me_wmutex) {
			rc = ErrCode();
			goto fail;
		}
#endif
	}
	return MDB_SUCCESS;

fail:
	close(env->me_lfd);
	env->me_lfd = INVALID_HANDLE_VALUE;
	return rc;

}

#define LOCKNAME	"/lock.mdb"
#define DATANAME	"/data.mdb"
int
mdb_env_open(MDB_env *env, const char *path, unsigned int flags, mode_t mode)
{
	int		oflags, rc, len, excl;
	char *lpath, *dpath;

	len = strlen(path);
	lpath = malloc(len + sizeof(LOCKNAME) + len + sizeof(DATANAME));
	if (!lpath)
		return ENOMEM;
	dpath = lpath + len + sizeof(LOCKNAME);
	sprintf(lpath, "%s" LOCKNAME, path);
	sprintf(dpath, "%s" DATANAME, path);

	rc = mdb_env_setup_locks(env, lpath, mode, &excl);
	if (rc)
		goto leave;

#ifdef _WIN32
	if (F_ISSET(flags, MDB_RDONLY)) {
		oflags = GENERIC_READ;
		len = OPEN_EXISTING;
	} else {
		oflags = GENERIC_READ|GENERIC_WRITE;
		len = OPEN_ALWAYS;
	}
	mode = FILE_ATTRIBUTE_NORMAL;
	if ((env->me_fd = CreateFile(dpath, oflags, FILE_SHARE_READ|FILE_SHARE_WRITE,
			NULL, len, mode, NULL)) == INVALID_HANDLE_VALUE) {
		rc = ErrCode();
		goto leave;
	}
#else
	if (F_ISSET(flags, MDB_RDONLY))
		oflags = O_RDONLY;
	else
		oflags = O_RDWR | O_CREAT;

	if ((env->me_fd = open(dpath, oflags, mode)) == -1) {
		rc = ErrCode();
		goto leave;
	}
#endif

	if ((rc = mdb_env_open2(env, flags)) == MDB_SUCCESS) {
		/* synchronous fd for meta writes */
#ifdef _WIN32
		if (!(flags & (MDB_RDONLY|MDB_NOSYNC)))
			mode |= FILE_FLAG_WRITE_THROUGH;
		if ((env->me_mfd = CreateFile(dpath, oflags, FILE_SHARE_READ|FILE_SHARE_WRITE,
			NULL, len, mode, NULL)) == INVALID_HANDLE_VALUE) {
			rc = ErrCode();
			goto leave;
		}
#else
		if (!(flags & (MDB_RDONLY|MDB_NOSYNC)))
			oflags |= MDB_DSYNC;
		if ((env->me_mfd = open(dpath, oflags, mode)) == -1) {
			rc = ErrCode();
			goto leave;
		}
#endif
		env->me_path = strdup(path);
		DPRINTF("opened dbenv %p", (void *) env);
		pthread_key_create(&env->me_txkey, mdb_env_reader_dest);
		LAZY_RWLOCK_INIT(&env->me_dblock, NULL);
		if (excl)
			mdb_env_share_locks(env);
		env->me_dbxs = calloc(env->me_maxdbs, sizeof(MDB_dbx));
		env->me_dbs[0] = calloc(env->me_maxdbs, sizeof(MDB_db));
		env->me_dbs[1] = calloc(env->me_maxdbs, sizeof(MDB_db));
		env->me_numdbs = 2;
	}

leave:
	if (rc) {
		if (env->me_fd != INVALID_HANDLE_VALUE) {
			close(env->me_fd);
			env->me_fd = INVALID_HANDLE_VALUE;
		}
		if (env->me_lfd != INVALID_HANDLE_VALUE) {
			close(env->me_lfd);
			env->me_lfd = INVALID_HANDLE_VALUE;
		}
	}
	free(lpath);
	return rc;
}

void
mdb_env_close(MDB_env *env)
{
	MDB_dpage *dp;

	if (env == NULL)
		return;

	while (env->me_dpages) {
		dp = env->me_dpages;
		env->me_dpages = (MDB_dpage *)dp->h.md_parent;
		free(dp);
	}

	free(env->me_dbs[1]);
	free(env->me_dbs[0]);
	free(env->me_dbxs);
	free(env->me_path);

	LAZY_RWLOCK_DESTROY(&env->me_dblock);
	pthread_key_delete(env->me_txkey);

	if (env->me_map) {
		munmap(env->me_map, env->me_mapsize);
	}
	close(env->me_mfd);
	close(env->me_fd);
	if (env->me_txns) {
		pid_t pid = getpid();
		unsigned int i;
		for (i=0; i<env->me_txns->mti_numreaders; i++)
			if (env->me_txns->mti_readers[i].mr_pid == pid)
				env->me_txns->mti_readers[i].mr_pid = 0;
		munmap(env->me_txns, (env->me_maxreaders-1)*sizeof(MDB_reader)+sizeof(MDB_txninfo));
	}
	close(env->me_lfd);
	free(env);
}

static int
intcmp(const MDB_val *a, const MDB_val *b)
{
	if (a->mv_size == sizeof(long))
	{
		unsigned long *la, *lb;
		la = a->mv_data;
		lb = b->mv_data;
		return *la - *lb;
	} else {
		unsigned int *ia, *ib;
		ia = a->mv_data;
		ib = b->mv_data;
		return *ia - *ib;
	}
}

static int
memncmp(const MDB_val *a, const MDB_val *b)
{
	int diff, len_diff;
	unsigned int len;

	len = a->mv_size;
	len_diff = a->mv_size - b->mv_size;
	if (len_diff > 0)
		len = b->mv_size;
	diff = memcmp(a->mv_data, b->mv_data, len);
	return diff ? diff : len_diff;
}

static int
memnrcmp(const MDB_val *a, const MDB_val *b)
{
	const unsigned char	*p1, *p2, *p1_lim;
	int diff, len_diff;

	if (b->mv_size == 0)
		return a->mv_size != 0;
	if (a->mv_size == 0)
		return -1;

	p1 = (const unsigned char *)a->mv_data + a->mv_size - 1;
	p2 = (const unsigned char *)b->mv_data + b->mv_size - 1;

	len_diff = a->mv_size - b->mv_size;
	if (len_diff < 0)
		p1_lim = p1 - a->mv_size;
	else
		p1_lim = p1 - b->mv_size;

	while (p1 >= p1_lim) {
		diff = *p1 - *p2;
		if (diff)
			return diff;
		p1--;
		p2--;
	}
	return len_diff;
}

/* Search for key within a leaf page, using binary search.
 * Returns the smallest entry larger or equal to the key.
 * If exactp is non-null, stores whether the found entry was an exact match
 * in *exactp (1 or 0).
 * If kip is non-null, stores the index of the found entry in *kip.
 * If no entry larger or equal to the key is found, returns NULL.
 */
static MDB_node *
mdb_search_node(MDB_txn *txn, MDB_dbi dbi, MDB_page *mp, MDB_val *key,
    int *exactp, unsigned int *kip)
{
	unsigned int	 i = 0, nkeys;
	int		 low, high;
	int		 rc = 0;
	MDB_node	*node = NULL;
	MDB_val	 nodekey;
	MDB_cmp_func *cmp;
	DKBUF;

	nkeys = NUMKEYS(mp);

	DPRINTF("searching %u keys in %s page %lu",
	    nkeys, IS_LEAF(mp) ? "leaf" : "branch",
	    mp->mp_pgno);

	assert(nkeys > 0);

	low = IS_LEAF(mp) ? 0 : 1;
	high = nkeys - 1;
	cmp = txn->mt_dbxs[dbi].md_cmp;
	if (IS_LEAF2(mp)) {
		nodekey.mv_size = txn->mt_dbs[dbi].md_pad;
		node = NODEPTR(mp, 0);	/* fake */
	}
	while (low <= high) {
		i = (low + high) >> 1;

		if (IS_LEAF2(mp)) {
			nodekey.mv_data = LEAF2KEY(mp, i, nodekey.mv_size);
		} else {
			node = NODEPTR(mp, i);

			nodekey.mv_size = node->mn_ksize;
			nodekey.mv_data = NODEKEY(node);
		}

		rc = cmp(key, &nodekey);

#if DEBUG
		if (IS_LEAF(mp))
			DPRINTF("found leaf index %u [%s], rc = %i",
			    i, DKEY(&nodekey), rc);
		else
			DPRINTF("found branch index %u [%s -> %lu], rc = %i",
			    i, DKEY(&nodekey), NODEPGNO(node), rc);
#endif

		if (rc == 0)
			break;
		if (rc > 0)
			low = i + 1;
		else
			high = i - 1;
	}

	if (rc > 0) {	/* Found entry is less than the key. */
		i++;	/* Skip to get the smallest entry larger than key. */
	}
	if (exactp)
		*exactp = (rc == 0);
	if (kip)	/* Store the key index if requested. */
		*kip = i;
	if (i >= nkeys)
		/* There is no entry larger or equal to the key. */
		return NULL;

	/* nodeptr is fake for LEAF2 */
	return node;
}

static void
cursor_pop_page(MDB_cursor *cursor)
{
	MDB_ppage	*top;

	if (cursor->mc_snum) {
		top = CURSOR_TOP(cursor);
		cursor->mc_snum--;

		DPRINTF("popped page %lu off db %u cursor %p", top->mp_page->mp_pgno,
			cursor->mc_dbi, (void *) cursor);
	}
}

static MDB_ppage *
cursor_push_page(MDB_cursor *cursor, MDB_page *mp)
{
	MDB_ppage	*ppage;

	DPRINTF("pushing page %lu on db %u cursor %p", mp->mp_pgno,
		cursor->mc_dbi, (void *) cursor);

	assert(cursor->mc_snum < CURSOR_STACK);

	ppage = &cursor->mc_stack[cursor->mc_snum++];
	ppage->mp_page = mp;
	ppage->mp_ki = 0;
	return ppage;
}

static int
mdb_get_page(MDB_txn *txn, pgno_t pgno, MDB_page **ret)
{
	MDB_page *p = NULL;

	if (!F_ISSET(txn->mt_flags, MDB_TXN_RDONLY) && txn->mt_u.dirty_list[0].mid) {
		MDB_dpage *dp;
		unsigned x;
		x = mdb_mid2l_search(txn->mt_u.dirty_list, pgno);
		if (x <= txn->mt_u.dirty_list[0].mid && txn->mt_u.dirty_list[x].mid == pgno) {
			dp = txn->mt_u.dirty_list[x].mptr;
			p = &dp->p;
		}
	}
	if (!p) {
		if (pgno <= txn->mt_env->me_metas[txn->mt_toggle]->mm_last_pg)
			p = (MDB_page *)(txn->mt_env->me_map + txn->mt_env->me_psize * pgno);
	}
	*ret = p;
	if (!p) {
		DPRINTF("page %lu not found", pgno);
		assert(p != NULL);
	}
	return (p != NULL) ? MDB_SUCCESS : MDB_PAGE_NOTFOUND;
}

static int
mdb_search_page_root(MDB_txn *txn, MDB_dbi dbi, MDB_val *key,
    MDB_cursor *cursor, int modify, MDB_pageparent *mpp)
{
	MDB_page	*mp = mpp->mp_page;
	DKBUF;
	int rc;

	if (cursor && cursor_push_page(cursor, mp) == NULL)
		return ENOMEM;

	while (IS_BRANCH(mp)) {
		unsigned int	 i = 0;
		MDB_node	*node;

		DPRINTF("branch page %lu has %u keys", mp->mp_pgno, NUMKEYS(mp));
		assert(NUMKEYS(mp) > 1);
		DPRINTF("found index 0 to page %lu", NODEPGNO(NODEPTR(mp, 0)));

		if (key == NULL)	/* Initialize cursor to first page. */
			i = 0;
		else if (key->mv_size > MAXKEYSIZE && key->mv_data == NULL) {
							/* cursor to last page */
			i = NUMKEYS(mp)-1;
		} else {
			int	 exact;
			node = mdb_search_node(txn, dbi, mp, key, &exact, &i);
			if (node == NULL)
				i = NUMKEYS(mp) - 1;
			else if (!exact) {
				assert(i > 0);
				i--;
			}
		}

		if (key)
			DPRINTF("following index %u for key [%s]",
			    i, DKEY(key));
		assert(i < NUMKEYS(mp));
		node = NODEPTR(mp, i);

		if (cursor)
			CURSOR_TOP(cursor)->mp_ki = i;

		mpp->mp_parent = mp;
		if ((rc = mdb_get_page(txn, NODEPGNO(node), &mp)))
			return rc;
		mpp->mp_pi = i;
		mpp->mp_page = mp;

		if (cursor && cursor_push_page(cursor, mp) == NULL)
			return ENOMEM;

		if (modify) {
			MDB_dhead *dh;
			if ((rc = mdb_touch(txn, dbi, mpp)) != 0)
				return rc;
			dh = ((MDB_dhead *)mpp->mp_page)-1;
			dh->md_parent = mpp->mp_parent;
			dh->md_pi = mpp->mp_pi;
		}

		mp = mpp->mp_page;
	}

	if (!IS_LEAF(mp)) {
		DPRINTF("internal error, index points to a %02X page!?",
		    mp->mp_flags);
		return MDB_CORRUPTED;
	}

	DPRINTF("found leaf page %lu for key [%s]", mp->mp_pgno,
	    key ? DKEY(key) : NULL);

	return MDB_SUCCESS;
}

/* Search for the page a given key should be in.
 * Stores a pointer to the found page in *mpp.
 * If key is NULL, search for the lowest page (used by mdb_cursor_first).
 * If cursor is non-null, pushes parent pages on the cursor stack.
 * If modify is true, visited pages are updated with new page numbers.
 */
static int
mdb_search_page(MDB_txn *txn, MDB_dbi dbi, MDB_val *key,
    MDB_cursor *cursor, int modify, MDB_pageparent *mpp)
{
	int		 rc;
	pgno_t		 root;

	/* Choose which root page to start with. If a transaction is given
	 * use the root page from the transaction, otherwise read the last
	 * committed root page.
	 */
	if (F_ISSET(txn->mt_flags, MDB_TXN_ERROR)) {
		DPUTS("transaction has failed, must abort");
		return EINVAL;
	} else
		root = txn->mt_dbs[dbi].md_root;

	if (root == P_INVALID) {		/* Tree is empty. */
		DPUTS("tree is empty");
		return MDB_NOTFOUND;
	}

	if ((rc = mdb_get_page(txn, root, &mpp->mp_page)))
		return rc;

	DPRINTF("db %u root page %lu has flags 0x%X",
		dbi, root,  mpp->mp_page->mp_flags);

	if (modify) {
		/* For sub-databases, update main root first */
		if (dbi > MAIN_DBI && !txn->mt_dbxs[dbi].md_dirty) {
			MDB_pageparent mp2;
			rc = mdb_search_page(txn, MAIN_DBI, &txn->mt_dbxs[dbi].md_name,
				NULL, 1, &mp2);
			if (rc)
				return rc;
			txn->mt_dbxs[dbi].md_dirty = 1;
		}
		if (!F_ISSET(mpp->mp_page->mp_flags, P_DIRTY)) {
			mpp->mp_parent = NULL;
			mpp->mp_pi = 0;
			if ((rc = mdb_touch(txn, dbi, mpp)))
				return rc;
			txn->mt_dbs[dbi].md_root = mpp->mp_page->mp_pgno;
		}
	}

	return mdb_search_page_root(txn, dbi, key, cursor, modify, mpp);
}

static int
mdb_read_data(MDB_txn *txn, MDB_node *leaf, MDB_val *data)
{
	MDB_page	*omp;		/* overflow mpage */
	pgno_t		 pgno;
	int rc;

	if (!F_ISSET(leaf->mn_flags, F_BIGDATA)) {
		data->mv_size = leaf->mn_dsize;
		data->mv_data = NODEDATA(leaf);
		return MDB_SUCCESS;
	}

	/* Read overflow data.
	 */
	data->mv_size = leaf->mn_dsize;
	memcpy(&pgno, NODEDATA(leaf), sizeof(pgno));
	if ((rc = mdb_get_page(txn, pgno, &omp))) {
		DPRINTF("read overflow page %lu failed", pgno);
		return rc;
	}
	data->mv_data = METADATA(omp);

	return MDB_SUCCESS;
}

int
mdb_get(MDB_txn *txn, MDB_dbi dbi,
    MDB_val *key, MDB_val *data)
{
	MDB_cursor	mc;
	MDB_xcursor	mx;
	int exact;
	DKBUF;

	assert(key);
	assert(data);
	DPRINTF("===> get db %u key [%s]", dbi, DKEY(key));

	if (txn == NULL || !dbi || dbi >= txn->mt_numdbs)
		return EINVAL;

	if (key->mv_size == 0 || key->mv_size > MAXKEYSIZE) {
		return EINVAL;
	}

	mc.mc_txn = txn;
	mc.mc_dbi = dbi;
	mc.mc_flags = 0;
	if (txn->mt_dbs[dbi].md_flags & MDB_DUPSORT) {
		mc.mc_xcursor = &mx;
		mdb_xcursor_init0(&mc);
	} else {
		mc.mc_xcursor = NULL;
	}
	return mdb_cursor_set(&mc, key, data, MDB_SET, &exact);
}

static int
mdb_sibling(MDB_cursor *cursor, int move_right)
{
	int		 rc;
	MDB_node	*indx;
	MDB_ppage	*parent;
	MDB_page	*mp;

	if (cursor->mc_snum < 2) {
		return MDB_NOTFOUND;		/* root has no siblings */
	}
	parent = CURSOR_PARENT(cursor);

	DPRINTF("parent page is page %lu, index %u",
	    parent->mp_page->mp_pgno, parent->mp_ki);

	cursor_pop_page(cursor);
	if (move_right ? (parent->mp_ki + 1 >= NUMKEYS(parent->mp_page))
		       : (parent->mp_ki == 0)) {
		DPRINTF("no more keys left, moving to %s sibling",
		    move_right ? "right" : "left");
		if ((rc = mdb_sibling(cursor, move_right)) != MDB_SUCCESS)
			return rc;
		parent = CURSOR_TOP(cursor);
	} else {
		if (move_right)
			parent->mp_ki++;
		else
			parent->mp_ki--;
		DPRINTF("just moving to %s index key %u",
		    move_right ? "right" : "left", parent->mp_ki);
	}
	assert(IS_BRANCH(parent->mp_page));

	indx = NODEPTR(parent->mp_page, parent->mp_ki);
	if ((rc = mdb_get_page(cursor->mc_txn, NODEPGNO(indx), &mp)))
		return rc;;
#if 0
	mp->parent = parent->mp_page;
	mp->parent_index = parent->mp_ki;
#endif

	cursor_push_page(cursor, mp);

	return MDB_SUCCESS;
}

static int
mdb_cursor_next(MDB_cursor *cursor, MDB_val *key, MDB_val *data, MDB_cursor_op op)
{
	MDB_ppage	*top;
	MDB_page	*mp;
	MDB_node	*leaf;
	int rc;

	if (cursor->mc_flags & C_EOF) {
		return MDB_NOTFOUND;
	}

	assert(cursor->mc_flags & C_INITIALIZED);

	top = CURSOR_TOP(cursor);
	mp = top->mp_page;

	if (cursor->mc_txn->mt_dbs[cursor->mc_dbi].md_flags & MDB_DUPSORT) {
		leaf = NODEPTR(mp, top->mp_ki);
		if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
			if (op == MDB_NEXT || op == MDB_NEXT_DUP) {
				rc = mdb_cursor_next(&cursor->mc_xcursor->mx_cursor, data, NULL, MDB_NEXT);
				if (op != MDB_NEXT || rc == MDB_SUCCESS)
					return rc;
			}
		} else {
			cursor->mc_xcursor->mx_cursor.mc_flags = 0;
			if (op == MDB_NEXT_DUP)
				return MDB_NOTFOUND;
		}
	}

	DPRINTF("cursor_next: top page is %lu in cursor %p", mp->mp_pgno, (void *) cursor);

	if (top->mp_ki + 1 >= NUMKEYS(mp)) {
		DPUTS("=====> move to next sibling page");
		if (mdb_sibling(cursor, 1) != MDB_SUCCESS) {
			cursor->mc_flags |= C_EOF;
			return MDB_NOTFOUND;
		}
		top = CURSOR_TOP(cursor);
		mp = top->mp_page;
		DPRINTF("next page is %lu, key index %u", mp->mp_pgno, top->mp_ki);
	} else
		top->mp_ki++;

	DPRINTF("==> cursor points to page %lu with %u keys, key index %u",
	    mp->mp_pgno, NUMKEYS(mp), top->mp_ki);

	if (IS_LEAF2(mp)) {
		key->mv_size = cursor->mc_txn->mt_dbs[cursor->mc_dbi].md_pad;
		key->mv_data = LEAF2KEY(mp, top->mp_ki, key->mv_size);
		return MDB_SUCCESS;
	}

	assert(IS_LEAF(mp));
	leaf = NODEPTR(mp, top->mp_ki);

	if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
		mdb_xcursor_init1(cursor, mp, leaf);
	}
	if (data) {
		if ((rc = mdb_read_data(cursor->mc_txn, leaf, data) != MDB_SUCCESS))
			return rc;

		if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
			rc = mdb_cursor_first(&cursor->mc_xcursor->mx_cursor, data, NULL);
			if (rc != MDB_SUCCESS)
				return rc;
		}
	}

	MDB_SET_KEY(leaf, key);
	return MDB_SUCCESS;
}

static int
mdb_cursor_prev(MDB_cursor *cursor, MDB_val *key, MDB_val *data, MDB_cursor_op op)
{
	MDB_ppage	*top;
	MDB_page	*mp;
	MDB_node	*leaf;
	int rc;

	assert(cursor->mc_flags & C_INITIALIZED);

	top = CURSOR_TOP(cursor);
	mp = top->mp_page;

	if (cursor->mc_txn->mt_dbs[cursor->mc_dbi].md_flags & MDB_DUPSORT) {
		leaf = NODEPTR(mp, top->mp_ki);
		if (op == MDB_PREV || op == MDB_PREV_DUP) {
			if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
				rc = mdb_cursor_prev(&cursor->mc_xcursor->mx_cursor, data, NULL, MDB_PREV);
				if (op != MDB_PREV || rc == MDB_SUCCESS)
					return rc;
			} else {
				cursor->mc_xcursor->mx_cursor.mc_flags = 0;
				if (op == MDB_PREV_DUP)
					return MDB_NOTFOUND;
			}
		}
	}

	DPRINTF("cursor_prev: top page is %lu in cursor %p", mp->mp_pgno, (void *) cursor);

	if (top->mp_ki == 0)  {
		DPUTS("=====> move to prev sibling page");
		if (mdb_sibling(cursor, 0) != MDB_SUCCESS) {
			cursor->mc_flags &= ~C_INITIALIZED;
			return MDB_NOTFOUND;
		}
		top = CURSOR_TOP(cursor);
		mp = top->mp_page;
		top->mp_ki = NUMKEYS(mp) - 1;
		DPRINTF("prev page is %lu, key index %u", mp->mp_pgno, top->mp_ki);
	} else
		top->mp_ki--;

	cursor->mc_flags &= ~C_EOF;

	DPRINTF("==> cursor points to page %lu with %u keys, key index %u",
	    mp->mp_pgno, NUMKEYS(mp), top->mp_ki);

	if (IS_LEAF2(mp)) {
		key->mv_size = cursor->mc_txn->mt_dbs[cursor->mc_dbi].md_pad;
		key->mv_data = LEAF2KEY(mp, top->mp_ki, key->mv_size);
		return MDB_SUCCESS;
	}

	assert(IS_LEAF(mp));
	leaf = NODEPTR(mp, top->mp_ki);

	if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
		mdb_xcursor_init1(cursor, mp, leaf);
	}
	if (data) {
		if ((rc = mdb_read_data(cursor->mc_txn, leaf, data) != MDB_SUCCESS))
			return rc;

		if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
			rc = mdb_cursor_last(&cursor->mc_xcursor->mx_cursor, data, NULL);
			if (rc != MDB_SUCCESS)
				return rc;
		}
	}

	MDB_SET_KEY(leaf, key);
	return MDB_SUCCESS;
}

static int
mdb_cursor_set(MDB_cursor *cursor, MDB_val *key, MDB_val *data,
    MDB_cursor_op op, int *exactp)
{
	int		 rc;
	MDB_node	*leaf;
	MDB_ppage	*top;
	MDB_pageparent mpp;
	DKBUF;

	assert(cursor);
	assert(key);
	assert(key->mv_size > 0);

	/* See if we're already on the right page */
	if (cursor->mc_flags & C_INITIALIZED) {
		MDB_val nodekey;

		top = CURSOR_TOP(cursor);
		if (top->mp_page->mp_flags & P_LEAF2) {
			nodekey.mv_size = cursor->mc_txn->mt_dbs[cursor->mc_dbi].md_pad;
			nodekey.mv_data = LEAF2KEY(top->mp_page, 0, nodekey.mv_size);
		} else {
			leaf = NODEPTR(top->mp_page, 0);
			MDB_SET_KEY(leaf, &nodekey);
		}
		rc = cursor->mc_txn->mt_dbxs[cursor->mc_dbi].md_cmp(key, &nodekey);
		if (rc == 0) {
set1:
			/* we're already on the right page */
			mpp.mp_page = top->mp_page;
			rc = 0;
			goto set2;
		}
		if (rc > 0) {
			unsigned int i;
			if (NUMKEYS(top->mp_page) > 1) {
				if (top->mp_page->mp_flags & P_LEAF2) {
					nodekey.mv_data = LEAF2KEY(top->mp_page,
						 NUMKEYS(top->mp_page)-1, nodekey.mv_size);
				} else {
					leaf = NODEPTR(top->mp_page, NUMKEYS(top->mp_page)-1);
					MDB_SET_KEY(leaf, &nodekey);
				}
				rc = cursor->mc_txn->mt_dbxs[cursor->mc_dbi].md_cmp(key, &nodekey);
				if (rc <= 0) goto set1;
			}
			/* If any parents have right-sibs, search.
			 * Otherwise, there's nothing further.
			 */
			for (i=0; i<cursor->mc_snum-1; i++)
				if (cursor->mc_stack[i].mp_ki <
					NUMKEYS(cursor->mc_stack[i].mp_page)-1)
					break;
			if (i == cursor->mc_snum - 1) {
				/* There are no other pages */
				goto set1;
			}
		}
	}

	cursor->mc_snum = 0;

	rc = mdb_search_page(cursor->mc_txn, cursor->mc_dbi, key, cursor, 0, &mpp);
	if (rc != MDB_SUCCESS)
		return rc;

	assert(IS_LEAF(mpp.mp_page));

	top = CURSOR_TOP(cursor);
set2:
	leaf = mdb_search_node(cursor->mc_txn, cursor->mc_dbi, mpp.mp_page, key, exactp, &top->mp_ki);
	if (exactp != NULL && !*exactp) {
		/* MDB_SET specified and not an exact match. */
		return MDB_NOTFOUND;
	}

	if (leaf == NULL) {
		DPUTS("===> inexact leaf not found, goto sibling");
		if ((rc = mdb_sibling(cursor, 1)) != MDB_SUCCESS)
			return rc;		/* no entries matched */
		top = CURSOR_TOP(cursor);
		top->mp_ki = 0;
		mpp.mp_page = top->mp_page;
		assert(IS_LEAF(mpp.mp_page));
		leaf = NODEPTR(mpp.mp_page, 0);
	}

	cursor->mc_flags |= C_INITIALIZED;
	cursor->mc_flags &= ~C_EOF;

	if (IS_LEAF2(mpp.mp_page)) {
		key->mv_size = cursor->mc_txn->mt_dbs[cursor->mc_dbi].md_pad;
		key->mv_data = LEAF2KEY(mpp.mp_page, top->mp_ki, key->mv_size);
		return MDB_SUCCESS;
	}

	if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
		mdb_xcursor_init1(cursor, mpp.mp_page, leaf);
	}
	if (data) {
		if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
			if (op == MDB_SET || op == MDB_SET_RANGE) {
				rc = mdb_cursor_first(&cursor->mc_xcursor->mx_cursor, data, NULL);
			} else {
				int ex2, *ex2p;
				if (op == MDB_GET_BOTH) {
					ex2p = &ex2;
					ex2 = 0;
				} else {
					ex2p = NULL;
				}
				rc = mdb_cursor_set(&cursor->mc_xcursor->mx_cursor, data, NULL, MDB_SET_RANGE, ex2p);
				if (rc != MDB_SUCCESS)
					return rc;
			}
		} else if (op == MDB_GET_BOTH || op == MDB_GET_BOTH_RANGE) {
			MDB_val d2;
			if ((rc = mdb_read_data(cursor->mc_txn, leaf, &d2)) != MDB_SUCCESS)
				return rc;
			rc = cursor->mc_txn->mt_dbxs[cursor->mc_dbi].md_cmp(data, &d2);
			if (rc) {
				if (op == MDB_GET_BOTH || rc > 0)
					return MDB_NOTFOUND;
			}

		} else {
			if ((rc = mdb_read_data(cursor->mc_txn, leaf, data)) != MDB_SUCCESS)
				return rc;
		}
	}

	/* The key already matches in all other cases */
	if (op == MDB_SET_RANGE)
		MDB_SET_KEY(leaf, key);
	DPRINTF("==> cursor placed on key [%s]", DKEY(key));

	return rc;
}

static int
mdb_cursor_first(MDB_cursor *cursor, MDB_val *key, MDB_val *data)
{
	int		 rc;
	MDB_pageparent	mpp;
	MDB_node	*leaf;

	cursor->mc_snum = 0;

	rc = mdb_search_page(cursor->mc_txn, cursor->mc_dbi, NULL, cursor, 0, &mpp);
	if (rc != MDB_SUCCESS)
		return rc;
	assert(IS_LEAF(mpp.mp_page));

	leaf = NODEPTR(mpp.mp_page, 0);
	cursor->mc_flags |= C_INITIALIZED;
	cursor->mc_flags &= ~C_EOF;

	if (IS_LEAF2(mpp.mp_page)) {
		key->mv_size = cursor->mc_txn->mt_dbs[cursor->mc_dbi].md_pad;
		key->mv_data = LEAF2KEY(mpp.mp_page, 0, key->mv_size);
		return MDB_SUCCESS;
	}

	if (data) {
		if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
			mdb_xcursor_init1(cursor, mpp.mp_page, leaf);
			rc = mdb_cursor_first(&cursor->mc_xcursor->mx_cursor, data, NULL);
			if (rc)
				return rc;
		} else {
			if (cursor->mc_xcursor)
				cursor->mc_xcursor->mx_cursor.mc_flags = 0;
			if ((rc = mdb_read_data(cursor->mc_txn, leaf, data)) != MDB_SUCCESS)
				return rc;
		}
	}
	MDB_SET_KEY(leaf, key);
	return MDB_SUCCESS;
}

static int
mdb_cursor_last(MDB_cursor *cursor, MDB_val *key, MDB_val *data)
{
	int		 rc;
	MDB_ppage	*top;
	MDB_pageparent	mpp;
	MDB_node	*leaf;
	MDB_val	lkey;

	cursor->mc_snum = 0;

	lkey.mv_size = MAXKEYSIZE+1;
	lkey.mv_data = NULL;

	rc = mdb_search_page(cursor->mc_txn, cursor->mc_dbi, &lkey, cursor, 0, &mpp);
	if (rc != MDB_SUCCESS)
		return rc;
	assert(IS_LEAF(mpp.mp_page));

	leaf = NODEPTR(mpp.mp_page, NUMKEYS(mpp.mp_page)-1);
	cursor->mc_flags |= C_INITIALIZED;
	cursor->mc_flags &= ~C_EOF;

	top = CURSOR_TOP(cursor);
	top->mp_ki = NUMKEYS(top->mp_page) - 1;

	if (IS_LEAF2(mpp.mp_page)) {
		key->mv_size = cursor->mc_txn->mt_dbs[cursor->mc_dbi].md_pad;
		key->mv_data = LEAF2KEY(mpp.mp_page, top->mp_ki, key->mv_size);
		return MDB_SUCCESS;
	}

	if (data) {
		if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
			mdb_xcursor_init1(cursor, mpp.mp_page, leaf);
			rc = mdb_cursor_last(&cursor->mc_xcursor->mx_cursor, data, NULL);
			if (rc)
				return rc;
		} else {
			if ((rc = mdb_read_data(cursor->mc_txn, leaf, data)) != MDB_SUCCESS)
				return rc;
		}
	}

	MDB_SET_KEY(leaf, key);
	return MDB_SUCCESS;
}

int
mdb_cursor_get(MDB_cursor *cursor, MDB_val *key, MDB_val *data,
    MDB_cursor_op op)
{
	int		 rc;
	int		 exact = 0;

	assert(cursor);

	switch (op) {
	case MDB_GET_BOTH:
	case MDB_GET_BOTH_RANGE:
		if (data == NULL || cursor->mc_xcursor == NULL) {
			rc = EINVAL;
			break;
		}
		/* FALLTHRU */
	case MDB_SET:
	case MDB_SET_RANGE:
		if (key == NULL || key->mv_size == 0 || key->mv_size > MAXKEYSIZE) {
			rc = EINVAL;
		} else if (op == MDB_SET_RANGE)
			rc = mdb_cursor_set(cursor, key, data, op, NULL);
		else
			rc = mdb_cursor_set(cursor, key, data, op, &exact);
		break;
	case MDB_GET_MULTIPLE:
		if (data == NULL ||
			!(cursor->mc_txn->mt_dbs[cursor->mc_dbi].md_flags & MDB_DUPFIXED) ||
			!(cursor->mc_flags & C_INITIALIZED)) {
			rc = EINVAL;
			break;
		}
		rc = MDB_SUCCESS;
		if (!(cursor->mc_xcursor->mx_cursor.mc_flags & C_INITIALIZED) ||
			(cursor->mc_xcursor->mx_cursor.mc_flags & C_EOF))
			break;
		goto fetchm;
	case MDB_NEXT_MULTIPLE:
		if (data == NULL ||
			!(cursor->mc_txn->mt_dbs[cursor->mc_dbi].md_flags & MDB_DUPFIXED)) {
			rc = EINVAL;
			break;
		}
		if (!(cursor->mc_flags & C_INITIALIZED))
			rc = mdb_cursor_first(cursor, key, data);
		else
			rc = mdb_cursor_next(cursor, key, data, MDB_NEXT_DUP);
		if (rc == MDB_SUCCESS) {
			if (cursor->mc_xcursor->mx_cursor.mc_flags & C_INITIALIZED) {
				MDB_ppage	*top;
fetchm:
				top = CURSOR_TOP(&cursor->mc_xcursor->mx_cursor);
				data->mv_size = NUMKEYS(top->mp_page) *
					cursor->mc_xcursor->mx_txn.mt_dbs[cursor->mc_xcursor->mx_cursor.mc_dbi].md_pad;
				data->mv_data = METADATA(top->mp_page);
				top->mp_ki = NUMKEYS(top->mp_page)-1;
			} else {
				rc = MDB_NOTFOUND;
			}
		}
		break;
	case MDB_NEXT:
	case MDB_NEXT_DUP:
	case MDB_NEXT_NODUP:
		if (!(cursor->mc_flags & C_INITIALIZED))
			rc = mdb_cursor_first(cursor, key, data);
		else
			rc = mdb_cursor_next(cursor, key, data, op);
		break;
	case MDB_PREV:
	case MDB_PREV_DUP:
	case MDB_PREV_NODUP:
		if (!(cursor->mc_flags & C_INITIALIZED) || (cursor->mc_flags & C_EOF))
			rc = mdb_cursor_last(cursor, key, data);
		else
			rc = mdb_cursor_prev(cursor, key, data, op);
		break;
	case MDB_FIRST:
		rc = mdb_cursor_first(cursor, key, data);
		break;
	case MDB_FIRST_DUP:
		if (data == NULL ||
			!(cursor->mc_txn->mt_dbs[cursor->mc_dbi].md_flags & MDB_DUPSORT) ||
			!(cursor->mc_flags & C_INITIALIZED) ||
			!(cursor->mc_xcursor->mx_cursor.mc_flags & C_INITIALIZED)) {
			rc = EINVAL;
			break;
		}
		rc = mdb_cursor_first(&cursor->mc_xcursor->mx_cursor, data, NULL);
		break;
	case MDB_LAST:
		rc = mdb_cursor_last(cursor, key, data);
		break;
	case MDB_LAST_DUP:
		if (data == NULL ||
			!(cursor->mc_txn->mt_dbs[cursor->mc_dbi].md_flags & MDB_DUPSORT) ||
			!(cursor->mc_flags & C_INITIALIZED) ||
			!(cursor->mc_xcursor->mx_cursor.mc_flags & C_INITIALIZED)) {
			rc = EINVAL;
			break;
		}
		rc = mdb_cursor_last(&cursor->mc_xcursor->mx_cursor, data, NULL);
		break;
	default:
		DPRINTF("unhandled/unimplemented cursor operation %u", op);
		rc = EINVAL;
		break;
	}

	return rc;
}

static int
mdb_cursor_touch(MDB_cursor *mc)
{
	MDB_pageparent mpp;
	MDB_dhead *dh;
	unsigned int i;
	int rc;

	mpp.mp_parent = NULL;
	mpp.mp_pi = 0;
	if (mc->mc_dbi > MAIN_DBI && !mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dirty) {
		rc = mdb_search_page(mc->mc_txn, MAIN_DBI, &mc->mc_txn->mt_dbxs[mc->mc_dbi].md_name,
			NULL, 1, &mpp);
		if (rc) return rc;
		mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dirty = 1;
	}
	for(i=0; i<mc->mc_snum; i++) {
		mpp.mp_page = mc->mc_stack[i].mp_page;
		if (!F_ISSET(mpp.mp_page->mp_flags, P_DIRTY)) {
			rc = mdb_touch(mc->mc_txn, mc->mc_dbi, &mpp);
			if (rc) return rc;
			mc->mc_stack[i].mp_page = mpp.mp_page;
			if (!i) {
				mc->mc_txn->mt_dbs[mc->mc_dbi].md_root = mpp.mp_page->mp_pgno;
			}
		}
		dh = ((MDB_dhead *)mpp.mp_page)-1;
		dh->md_parent = mpp.mp_parent;
		dh->md_pi = mpp.mp_pi;
		mpp.mp_parent = mpp.mp_page;
		mpp.mp_pi = mc->mc_stack[i].mp_ki;
	}
	return MDB_SUCCESS;
}

int
mdb_cursor_put(MDB_cursor *mc, MDB_val *key, MDB_val *data,
    unsigned int flags)
{
	MDB_ppage	*top;
	MDB_node	*leaf;
	MDB_val	xdata, *rdata, dkey;
	MDB_db dummy;
	char dbuf[PAGESIZE];
	int do_sub = 0;
	size_t nsize;
	DKBUF;
	int rc, rc2;

	if (F_ISSET(mc->mc_txn->mt_flags, MDB_TXN_RDONLY))
		return EACCES;

	DPRINTF("==> put db %u key [%s], size %zu, data size %zu",
		mc->mc_dbi, DKEY(key), key->mv_size, data->mv_size);

	dkey.mv_size = 0;

	if (flags == MDB_CURRENT) {
		if (!(mc->mc_flags & C_INITIALIZED))
			return EINVAL;
		rc = MDB_SUCCESS;
	} else if (mc->mc_txn->mt_dbs[mc->mc_dbi].md_root == P_INVALID) {
		MDB_dpage *dp;
		/* new database, write a root leaf page */
		DPUTS("allocating new root leaf page");
		if ((dp = mdb_new_page(mc->mc_txn, mc->mc_dbi, P_LEAF, 1)) == NULL) {
			return ENOMEM;
		}
		mc->mc_snum = 0;
		cursor_push_page(mc, &dp->p);
		mc->mc_txn->mt_dbs[mc->mc_dbi].md_root = dp->p.mp_pgno;
		mc->mc_txn->mt_dbs[mc->mc_dbi].md_depth++;
		mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dirty = 1;
		if ((mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags & (MDB_DUPSORT|MDB_DUPFIXED))
			== MDB_DUPFIXED)
			dp->p.mp_flags |= P_LEAF2;
		mc->mc_flags |= C_INITIALIZED;
		rc = MDB_NOTFOUND;
		goto top;
	} else {
		int exact = 0;
		rc = mdb_cursor_set(mc, key, NULL, MDB_SET, &exact);
		if (flags == MDB_NOOVERWRITE && rc == 0) {
			DPRINTF("duplicate key [%s]", DKEY(key));
			return MDB_KEYEXIST;
		}
		if (rc && rc != MDB_NOTFOUND)
			return rc;
	}

	/* Cursor is positioned, now make sure all pages are writable */
	rc2 = mdb_cursor_touch(mc);
	if (rc2) return rc2;

top:
	top = CURSOR_TOP(mc);

	/* The key already exists */
	if (rc == MDB_SUCCESS) {
		/* there's only a key anyway, so this is a no-op */
		if (IS_LEAF2(top->mp_page)) {
			unsigned int ksize = mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad;
			if (key->mv_size != ksize)
				return EINVAL;
			if (flags == MDB_CURRENT) {
				char *ptr = LEAF2KEY(top->mp_page, top->mp_ki, ksize);
				memcpy(ptr, key->mv_data, ksize);
			}
			return MDB_SUCCESS;
		}

		leaf = NODEPTR(top->mp_page, top->mp_ki);

		/* DB has dups? */
		if (F_ISSET(mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags, MDB_DUPSORT)) {
			/* Was a single item before, must convert now */
			if (!F_ISSET(leaf->mn_flags, F_DUPDATA)) {
				dkey.mv_size = NODEDSZ(leaf);
				dkey.mv_data = dbuf;
				memcpy(dbuf, NODEDATA(leaf), dkey.mv_size);
				/* data matches, ignore it */
				if (!mdb_dcmp(mc->mc_txn, mc->mc_dbi, data, &dkey))
					return (flags == MDB_NODUPDATA) ? MDB_KEYEXIST : MDB_SUCCESS;
				memset(&dummy, 0, sizeof(dummy));
				if (mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags & MDB_DUPFIXED) {
					dummy.md_pad = data->mv_size;
					dummy.md_flags = MDB_DUPFIXED;
					if (mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags & MDB_INTEGERDUP)
						dummy.md_flags |= MDB_INTEGERKEY;
				}
				dummy.md_root = P_INVALID;
				if (dkey.mv_size == sizeof(MDB_db)) {
					memcpy(NODEDATA(leaf), &dummy, sizeof(dummy));
					goto put_sub;
				}
				mdb_del_node(top->mp_page, top->mp_ki, 0);
				do_sub = 1;
				rdata = &xdata;
				xdata.mv_size = sizeof(MDB_db);
				xdata.mv_data = &dummy;
				goto new_sub;
			}
			goto put_sub;
		}
		/* same size, just replace it */
		if (!F_ISSET(leaf->mn_flags, F_BIGDATA) &&
			NODEDSZ(leaf) == data->mv_size) {
			memcpy(NODEDATA(leaf), data->mv_data, data->mv_size);
			goto done;
		}
		mdb_del_node(top->mp_page, top->mp_ki, 0);
	} else {
		DPRINTF("inserting key at index %i", top->mp_ki);
	}

	rdata = data;

new_sub:
	nsize = IS_LEAF2(top->mp_page) ? key->mv_size : mdb_leaf_size(mc->mc_txn->mt_env, key, rdata);
	if (SIZELEFT(top->mp_page) < nsize) {
		rc = mdb_split(mc->mc_txn, mc->mc_dbi, &top->mp_page, &top->mp_ki, key, rdata, P_INVALID);
	} else {
		/* There is room already in this leaf page. */
		rc = mdb_add_node(mc->mc_txn, mc->mc_dbi, top->mp_page, top->mp_ki, key, rdata, 0, 0);
	}

	if (rc != MDB_SUCCESS)
		mc->mc_txn->mt_flags |= MDB_TXN_ERROR;
	else {
		/* Remember if we just added a subdatabase */
		if (flags & F_SUBDATA) {
			leaf = NODEPTR(top->mp_page, top->mp_ki);
			leaf->mn_flags |= F_SUBDATA;
		}

		/* Now store the actual data in the child DB. Note that we're
		 * storing the user data in the keys field, so there are strict
		 * size limits on dupdata. The actual data fields of the child
		 * DB are all zero size.
		 */
		if (do_sub) {
			leaf = NODEPTR(top->mp_page, top->mp_ki);
put_sub:
			if (flags == MDB_CURRENT)
				mdb_xcursor_init2(mc);
			else
				mdb_xcursor_init1(mc, top->mp_page, leaf);
			xdata.mv_size = 0;
			xdata.mv_data = "";
			if (flags == MDB_NODUPDATA)
				flags = MDB_NOOVERWRITE;
			/* converted, write the original data first */
			if (dkey.mv_size) {
				rc = mdb_cursor_put(&mc->mc_xcursor->mx_cursor, &dkey, &xdata, flags);
				if (rc) return rc;
				leaf->mn_flags |= F_DUPDATA;
			}
			rc = mdb_cursor_put(&mc->mc_xcursor->mx_cursor, data, &xdata, flags);
			mdb_xcursor_fini(mc);
			memcpy(NODEDATA(leaf),
				&mc->mc_xcursor->mx_txn.mt_dbs[mc->mc_xcursor->mx_cursor.mc_dbi],
				sizeof(MDB_db));
		}
		mc->mc_txn->mt_dbs[mc->mc_dbi].md_entries++;
	}
done:
	return rc;
}

int
mdb_cursor_del(MDB_cursor *mc, unsigned int flags)
{
	MDB_pageparent mpp;
	MDB_ppage	*top;
	MDB_node	*leaf;
	int rc;

	if (F_ISSET(mc->mc_txn->mt_flags, MDB_TXN_RDONLY))
		return EACCES;

	if (!mc->mc_flags & C_INITIALIZED)
		return EINVAL;

	rc = mdb_cursor_touch(mc);
	if (rc) return rc;

	top = CURSOR_TOP(mc);
	leaf = NODEPTR(top->mp_page, top->mp_ki);
	mpp.mp_page = top->mp_page;
	if (mc->mc_snum > 1) {
		MDB_ppage *parent = CURSOR_PARENT(mc);
		mpp.mp_parent = parent->mp_page;
		mpp.mp_pi = parent->mp_ki;
	} else {
		mpp.mp_parent = NULL;
		mpp.mp_pi = 0;
	}

	if (!IS_LEAF2(top->mp_page) && F_ISSET(leaf->mn_flags, F_DUPDATA)) {
		MDB_pageparent mp2;

		if (flags != MDB_NODUPDATA) {
/*			mdb_xcursor_init2(mc); */
			rc = mdb_cursor_del(&mc->mc_xcursor->mx_cursor, 0);
			mdb_xcursor_fini(mc);
			/* If sub-DB still has entries, we're done */
			if (mc->mc_xcursor->mx_txn.mt_dbs[mc->mc_xcursor->mx_cursor.mc_dbi].md_root
				!= P_INVALID) {
				memcpy(NODEDATA(leaf),
					&mc->mc_xcursor->mx_txn.mt_dbs[mc->mc_xcursor->mx_cursor.mc_dbi],
					sizeof(MDB_db));
				mc->mc_txn->mt_dbs[mc->mc_dbi].md_entries--;
				return rc;
			}
			/* otherwise fall thru and delete the sub-DB */
		}

		/* add all the child DB's pages to the free list */
		mc->mc_xcursor->mx_cursor.mc_snum = 0;
		rc = mdb_search_page(&mc->mc_xcursor->mx_txn, mc->mc_xcursor->mx_cursor.mc_dbi,
			NULL, &mc->mc_xcursor->mx_cursor, 0, &mp2);
		if (rc == MDB_SUCCESS) {
			MDB_ppage *top, *parent;
			MDB_node *ni;
			unsigned int i;
#if 0
			MDB_dpage *dp;
			ID2	mid;
			int dirty_root = 0;
#endif

			mc->mc_txn->mt_dbs[mc->mc_dbi].md_entries -=
				mc->mc_xcursor->mx_txn.mt_dbs[mc->mc_xcursor->mx_cursor.mc_dbi].md_entries;

			cursor_pop_page(&mc->mc_xcursor->mx_cursor);
			if (mc->mc_xcursor->mx_cursor.mc_snum) {
#if 0
				if (mc->mc_xcursor->mx_cursor.mc_stack[0].mp_page->mp_flags & P_DIRTY) {
					dirty_root = 1;
				}
#endif
				while (mc->mc_xcursor->mx_cursor.mc_snum > 1) {
					top = CURSOR_TOP(&mc->mc_xcursor->mx_cursor);
					parent = CURSOR_PARENT(&mc->mc_xcursor->mx_cursor);
					for (i=0; i<NUMKEYS(top->mp_page); i++) {
						MDB_page *mp;
						pgno_t pg;
						ni = NODEPTR(top->mp_page, i);
						pg = NODEPGNO(ni);
						if ((rc = mdb_get_page(mc->mc_txn, pg, &mp)))
							return rc;
#if 0
						if (mp->mp_flags & P_DIRTY) {
							/* drop it */
							mid.mid = pg;
							mdb_mid2l_delete(mc->mc_txn->mt_u.dirty_list, &mid);
							dp = mid.mptr;
							dp->h.md_parent = (MDB_page *)mc->mc_txn->mt_env->me_dpages;
							mc->mc_txn->mt_env->me_dpages = dp;
						} else
#endif
						{
							/* free it */
							mdb_midl_append(mc->mc_txn->mt_free_pgs, pg);
						}
					}
					rc = mdb_sibling(&mc->mc_xcursor->mx_cursor, 1);
					if (rc) break;
				}
			}
#if 0
			if (dirty_root) {
				/* drop it */
				mid.mid = mc->mc_xcursor->mx_txn.mt_dbs[mc->mc_xcursor->mx_cursor.mc_dbi].md_root;
				mdb_mid2l_delete(mc->mc_txn->mt_u.dirty_list, &mid);
				dp = mid.mptr;
				dp->h.md_parent = (MDB_page *)mc->mc_txn->mt_env->me_dpages;
				mc->mc_txn->mt_env->me_dpages = dp;
			} else
#endif
			{
				/* free it */
				mdb_midl_append(mc->mc_txn->mt_free_pgs,
					mc->mc_xcursor->mx_txn.mt_dbs[mc->mc_xcursor->mx_cursor.mc_dbi].md_root);
			}
		}
	}

	return mdb_del0(mc, top->mp_ki, &mpp, leaf);
}

/* Allocate a page and initialize it
 */
static MDB_dpage *
mdb_new_page(MDB_txn *txn, MDB_dbi dbi, uint32_t flags, int num)
{
	MDB_dpage	*dp;

	if ((dp = mdb_alloc_page(txn, dbi, NULL, 0, num)) == NULL)
		return NULL;
	DPRINTF("allocated new mpage %lu, page size %u",
	    dp->p.mp_pgno, txn->mt_env->me_psize);
	dp->p.mp_flags = flags | P_DIRTY;
	dp->p.mp_lower = PAGEHDRSZ;
	dp->p.mp_upper = txn->mt_env->me_psize;

	if (IS_BRANCH(&dp->p))
		txn->mt_dbs[dbi].md_branch_pages++;
	else if (IS_LEAF(&dp->p))
		txn->mt_dbs[dbi].md_leaf_pages++;
	else if (IS_OVERFLOW(&dp->p)) {
		txn->mt_dbs[dbi].md_overflow_pages += num;
		dp->p.mp_pages = num;
	}

	return dp;
}

static size_t
mdb_leaf_size(MDB_env *env, MDB_val *key, MDB_val *data)
{
	size_t		 sz;

	sz = LEAFSIZE(key, data);
	if (data->mv_size >= env->me_psize / MDB_MINKEYS) {
		/* put on overflow page */
		sz -= data->mv_size - sizeof(pgno_t);
	}

	return sz + sizeof(indx_t);
}

static size_t
mdb_branch_size(MDB_env *env, MDB_val *key)
{
	size_t		 sz;

	sz = INDXSIZE(key);
	if (sz >= env->me_psize / MDB_MINKEYS) {
		/* put on overflow page */
		/* not implemented */
		/* sz -= key->size - sizeof(pgno_t); */
	}

	return sz + sizeof(indx_t);
}

static int
mdb_add_node(MDB_txn *txn, MDB_dbi dbi, MDB_page *mp, indx_t indx,
    MDB_val *key, MDB_val *data, pgno_t pgno, uint8_t flags)
{
	unsigned int	 i;
	size_t		 node_size = NODESIZE;
	indx_t		 ofs;
	MDB_node	*node;
	MDB_dpage	*ofp = NULL;		/* overflow page */
	DKBUF;

	assert(mp->mp_upper >= mp->mp_lower);

	DPRINTF("add to %s page %lu index %i, data size %zu key size %zu [%s]",
	    IS_LEAF(mp) ? "leaf" : "branch",
	    mp->mp_pgno, indx, data ? data->mv_size : 0,
		key ? key->mv_size : 0, key ? DKEY(key) : NULL);

	if (IS_LEAF2(mp)) {
		/* Move higher keys up one slot. */
		int ksize = txn->mt_dbs[dbi].md_pad, dif;
		char *ptr = LEAF2KEY(mp, indx, ksize);
		dif = NUMKEYS(mp) - indx;
		if (dif > 0)
			memmove(ptr+ksize, ptr, dif*ksize);
		/* insert new key */
		memcpy(ptr, key->mv_data, ksize);

		/* Just using these for counting */
		mp->mp_lower += sizeof(indx_t);
		mp->mp_upper -= ksize - sizeof(indx_t);
		return MDB_SUCCESS;
	}

	if (key != NULL)
		node_size += key->mv_size;

	if (IS_LEAF(mp)) {
		assert(data);
		if (F_ISSET(flags, F_BIGDATA)) {
			/* Data already on overflow page. */
			node_size += sizeof(pgno_t);
		} else if (data->mv_size >= txn->mt_env->me_psize / MDB_MINKEYS) {
			int ovpages = OVPAGES(data->mv_size, txn->mt_env->me_psize);
			/* Put data on overflow page. */
			DPRINTF("data size is %zu, put on overflow page",
			    data->mv_size);
			node_size += sizeof(pgno_t);
			if ((ofp = mdb_new_page(txn, dbi, P_OVERFLOW, ovpages)) == NULL)
				return ENOMEM;
			DPRINTF("allocated overflow page %lu", ofp->p.mp_pgno);
			flags |= F_BIGDATA;
		} else {
			node_size += data->mv_size;
		}
	}

	if (node_size + sizeof(indx_t) > SIZELEFT(mp)) {
		DPRINTF("not enough room in page %lu, got %u ptrs",
		    mp->mp_pgno, NUMKEYS(mp));
		DPRINTF("upper - lower = %u - %u = %u", mp->mp_upper, mp->mp_lower,
		    mp->mp_upper - mp->mp_lower);
		DPRINTF("node size = %zu", node_size);
		return ENOSPC;
	}

	/* Move higher pointers up one slot. */
	for (i = NUMKEYS(mp); i > indx; i--)
		mp->mp_ptrs[i] = mp->mp_ptrs[i - 1];

	/* Adjust free space offsets. */
	ofs = mp->mp_upper - node_size;
	assert(ofs >= mp->mp_lower + sizeof(indx_t));
	mp->mp_ptrs[indx] = ofs;
	mp->mp_upper = ofs;
	mp->mp_lower += sizeof(indx_t);

	/* Write the node data. */
	node = NODEPTR(mp, indx);
	node->mn_ksize = (key == NULL) ? 0 : key->mv_size;
	node->mn_flags = flags;
	if (IS_LEAF(mp))
		node->mn_dsize = data->mv_size;
	else
		NODEPGNO(node) = pgno;

	if (key)
		memcpy(NODEKEY(node), key->mv_data, key->mv_size);

	if (IS_LEAF(mp)) {
		assert(key);
		if (ofp == NULL) {
			if (F_ISSET(flags, F_BIGDATA))
				memcpy(node->mn_data + key->mv_size, data->mv_data,
				    sizeof(pgno_t));
			else
				memcpy(node->mn_data + key->mv_size, data->mv_data,
				    data->mv_size);
		} else {
			memcpy(node->mn_data + key->mv_size, &ofp->p.mp_pgno,
			    sizeof(pgno_t));
			memcpy(METADATA(&ofp->p), data->mv_data, data->mv_size);
		}
	}

	return MDB_SUCCESS;
}

static void
mdb_del_node(MDB_page *mp, indx_t indx, int ksize)
{
	unsigned int	 sz;
	indx_t		 i, j, numkeys, ptr;
	MDB_node	*node;
	char		*base;

	DPRINTF("delete node %u on %s page %lu", indx,
	    IS_LEAF(mp) ? "leaf" : "branch", mp->mp_pgno);
	assert(indx < NUMKEYS(mp));

	if (IS_LEAF2(mp)) {
		int x = NUMKEYS(mp) - 1 - indx;
		base = LEAF2KEY(mp, indx, ksize);
		if (x)
			memmove(base, base + ksize, x * ksize);
		mp->mp_lower -= sizeof(indx_t);
		mp->mp_upper += ksize - sizeof(indx_t);
		return;
	}

	node = NODEPTR(mp, indx);
	sz = NODESIZE + node->mn_ksize;
	if (IS_LEAF(mp)) {
		if (F_ISSET(node->mn_flags, F_BIGDATA))
			sz += sizeof(pgno_t);
		else
			sz += NODEDSZ(node);
	}

	ptr = mp->mp_ptrs[indx];
	numkeys = NUMKEYS(mp);
	for (i = j = 0; i < numkeys; i++) {
		if (i != indx) {
			mp->mp_ptrs[j] = mp->mp_ptrs[i];
			if (mp->mp_ptrs[i] < ptr)
				mp->mp_ptrs[j] += sz;
			j++;
		}
	}

	base = (char *)mp + mp->mp_upper;
	memmove(base + sz, base, ptr - mp->mp_upper);

	mp->mp_lower -= sizeof(indx_t);
	mp->mp_upper += sz;
}

static void
mdb_xcursor_init0(MDB_cursor *mc)
{
	MDB_xcursor *mx = mc->mc_xcursor;
	MDB_dbi dbn;

	mx->mx_txn = *mc->mc_txn;
	mx->mx_txn.mt_dbxs = mx->mx_dbxs;
	mx->mx_txn.mt_dbs = mx->mx_dbs;
	mx->mx_dbxs[0] = mc->mc_txn->mt_dbxs[0];
	mx->mx_dbxs[1] = mc->mc_txn->mt_dbxs[1];
	if (mc->mc_dbi > 1) {
		mx->mx_dbxs[2] = mc->mc_txn->mt_dbxs[mc->mc_dbi];
		dbn = 2;
	} else {
		dbn = 1;
	}
	mx->mx_dbxs[dbn+1].md_parent = dbn;
	mx->mx_dbxs[dbn+1].md_cmp = mx->mx_dbxs[dbn].md_dcmp;
	mx->mx_dbxs[dbn+1].md_rel = mx->mx_dbxs[dbn].md_rel;
	mx->mx_dbxs[dbn+1].md_dirty = 0;
	mx->mx_txn.mt_numdbs = dbn+2;

	mx->mx_cursor.mc_xcursor = NULL;
	mx->mx_cursor.mc_txn = &mx->mx_txn;
	mx->mx_cursor.mc_dbi = dbn+1;
}

static void
mdb_xcursor_init1(MDB_cursor *mc, MDB_page *mp, MDB_node *node)
{
	MDB_db *db = NODEDATA(node);
	MDB_xcursor *mx = mc->mc_xcursor;
	MDB_dbi dbn;
	mx->mx_dbs[0] = mc->mc_txn->mt_dbs[0];
	mx->mx_dbs[1] = mc->mc_txn->mt_dbs[1];
	if (mc->mc_dbi > 1) {
		mx->mx_dbs[2] = mc->mc_txn->mt_dbs[mc->mc_dbi];
		dbn = 3;
	} else {
		dbn = 2;
	}
	DPRINTF("Sub-db %u for db %u root page %lu", dbn, mc->mc_dbi, db->md_root);
	mx->mx_dbs[dbn] = *db;
	if (F_ISSET(mp->mp_flags, P_DIRTY))
		mx->mx_dbxs[dbn].md_dirty = 1;
	mx->mx_dbxs[dbn].md_name.mv_data = NODEKEY(node);
	mx->mx_dbxs[dbn].md_name.mv_size = node->mn_ksize;
	mx->mx_txn.mt_next_pgno = mc->mc_txn->mt_next_pgno;
	mx->mx_txn.mt_u = mc->mc_txn->mt_u;
	mx->mx_cursor.mc_snum = 0;
	mx->mx_cursor.mc_flags = 0;
}

static void
mdb_xcursor_init2(MDB_cursor *mc)
{
	MDB_xcursor *mx = mc->mc_xcursor;
	MDB_dbi dbn;
	mx->mx_dbs[0] = mc->mc_txn->mt_dbs[0];
	mx->mx_dbs[1] = mc->mc_txn->mt_dbs[1];
	if (mc->mc_dbi > 1) {
		mx->mx_dbs[2] = mc->mc_txn->mt_dbs[mc->mc_dbi];
		dbn = 3;
	} else {
		dbn = 2;
	}
	DPRINTF("Sub-db %u for db %u root page %lu", dbn, mc->mc_dbi,
		mx->mx_dbs[dbn].md_root);
	mx->mx_txn.mt_next_pgno = mc->mc_txn->mt_next_pgno;
}

static void
mdb_xcursor_fini(MDB_cursor *mc)
{
	MDB_xcursor *mx = mc->mc_xcursor;
	mc->mc_txn->mt_next_pgno = mx->mx_txn.mt_next_pgno;
	mc->mc_txn->mt_dbs[0] = mx->mx_dbs[0];
	mc->mc_txn->mt_dbs[1] = mx->mx_dbs[1];
	mc->mc_txn->mt_dbxs[0].md_dirty = mx->mx_dbxs[0].md_dirty;
	mc->mc_txn->mt_dbxs[1].md_dirty = mx->mx_dbxs[1].md_dirty;
	if (mc->mc_dbi > 1) {
		mc->mc_txn->mt_dbs[mc->mc_dbi] = mx->mx_dbs[2];
		mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dirty = mx->mx_dbxs[2].md_dirty;
	}
}

int
mdb_cursor_open(MDB_txn *txn, MDB_dbi dbi, MDB_cursor **ret)
{
	MDB_cursor	*cursor;
	size_t size = sizeof(MDB_cursor);

	if (txn == NULL || ret == NULL || !dbi || dbi >= txn->mt_numdbs)
		return EINVAL;

	if (txn->mt_dbs[dbi].md_flags & MDB_DUPSORT)
		size += sizeof(MDB_xcursor);

	if ((cursor = calloc(1, size)) != NULL) {
		cursor->mc_dbi = dbi;
		cursor->mc_txn = txn;
		if (txn->mt_dbs[dbi].md_flags & MDB_DUPSORT) {
			MDB_xcursor *mx = (MDB_xcursor *)(cursor + 1);
			cursor->mc_xcursor = mx;
			mdb_xcursor_init0(cursor);
		}
	} else {
		return ENOMEM;
	}

	*ret = cursor;

	return MDB_SUCCESS;
}

/* Return the count of duplicate data items for the current key */
int
mdb_cursor_count(MDB_cursor *mc, unsigned long *countp)
{
	MDB_ppage	*top;
	MDB_node	*leaf;

	if (mc == NULL || countp == NULL)
		return EINVAL;

	if (!(mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags & MDB_DUPSORT))
		return EINVAL;

	top = CURSOR_TOP(mc);
	leaf = NODEPTR(top->mp_page, top->mp_ki);
	if (!F_ISSET(leaf->mn_flags, F_DUPDATA)) {
		*countp = 1;
	} else {
		if (!(mc->mc_xcursor->mx_cursor.mc_flags & C_INITIALIZED))
			return EINVAL;

		*countp = mc->mc_xcursor->mx_txn.mt_dbs[mc->mc_xcursor->mx_cursor.mc_dbi].md_entries;
	}
	return MDB_SUCCESS;
}

#if 0
static void
mdb_cursor_reset(MDB_cursor *mc)
{
	if (mc != NULL) {
		if (mc->mc_flags & C_XDIRTY) {

			mdb_xcursor_fini(mc);

			/* If sub-DB still has entries, update root record */
			if (mc->mc_xcursor->mx_txn.mt_dbs[mc->mc_xcursor->mx_cursor.mc_dbi].md_root
				!= P_INVALID) {
				MDB_ppage *top;
				MDB_node *leaf;
				top = CURSOR_TOP(mc);
				leaf = NODEPTR(top->mp_page, top->mp_ki);
				memcpy(NODEDATA(leaf),
					&mc->mc_xcursor->mx_txn.mt_dbs[mc->mc_xcursor->mx_cursor.mc_dbi],
					sizeof(MDB_db));
			}
			mc->mc_flags ^= C_XDIRTY;
		}
	}
}
#endif

void
mdb_cursor_close(MDB_cursor *cursor)
{
	if (cursor != NULL) {
		free(cursor);
	}
}

static int
mdb_update_key(MDB_page *mp, indx_t indx, MDB_val *key)
{
	indx_t			 ptr, i, numkeys;
	int			 delta;
	size_t			 len;
	MDB_node		*node;
	char			*base;
	DKBUF;

	node = NODEPTR(mp, indx);
	ptr = mp->mp_ptrs[indx];
	DPRINTF("update key %u (ofs %u) [%.*s] to [%s] on page %lu",
	    indx, ptr,
	    (int)node->mn_ksize, (char *)NODEKEY(node),
		DKEY(key),
	    mp->mp_pgno);

	delta = key->mv_size - node->mn_ksize;
	if (delta) {
		if (delta > 0 && SIZELEFT(mp) < delta) {
			DPRINTF("OUCH! Not enough room, delta = %d", delta);
			return ENOSPC;
		}

		numkeys = NUMKEYS(mp);
		for (i = 0; i < numkeys; i++) {
			if (mp->mp_ptrs[i] <= ptr)
				mp->mp_ptrs[i] -= delta;
		}

		base = (char *)mp + mp->mp_upper;
		len = ptr - mp->mp_upper + NODESIZE;
		memmove(base - delta, base, len);
		mp->mp_upper -= delta;

		node = NODEPTR(mp, indx);
		node->mn_ksize = key->mv_size;
	}

	memcpy(NODEKEY(node), key->mv_data, key->mv_size);

	return MDB_SUCCESS;
}

/* Move a node from src to dst.
 */
static int
mdb_move_node(MDB_txn *txn, MDB_dbi dbi, MDB_pageparent *src, indx_t srcindx,
    MDB_pageparent *dst, indx_t dstindx)
{
	int			 rc;
	MDB_node		*srcnode;
	MDB_val		 key, data;
	DKBUF;

	/* Mark src and dst as dirty. */
	if ((rc = mdb_touch(txn, dbi, src)) ||
	    (rc = mdb_touch(txn, dbi, dst)))
		return rc;;

	if (IS_LEAF2(src->mp_page)) {
		srcnode = NODEPTR(src->mp_page, 0);	/* fake */
		key.mv_size = txn->mt_dbs[dbi].md_pad;
		key.mv_data = LEAF2KEY(src->mp_page, srcindx, key.mv_size);
		data.mv_size = 0;
		data.mv_data = NULL;
	} else {
		srcnode = NODEPTR(src->mp_page, srcindx);
		key.mv_size = NODEKSZ(srcnode);
		key.mv_data = NODEKEY(srcnode);
		data.mv_size = NODEDSZ(srcnode);
		data.mv_data = NODEDATA(srcnode);
	}
	DPRINTF("moving %s node %u [%s] on page %lu to node %u on page %lu",
	    IS_LEAF(src->mp_page) ? "leaf" : "branch",
	    srcindx,
		DKEY(&key),
	    src->mp_page->mp_pgno,
	    dstindx, dst->mp_page->mp_pgno);

	/* Add the node to the destination page.
	 */
	rc = mdb_add_node(txn, dbi, dst->mp_page, dstindx, &key, &data, NODEPGNO(srcnode),
	    srcnode->mn_flags);
	if (rc != MDB_SUCCESS)
		return rc;

	/* Delete the node from the source page.
	 */
	mdb_del_node(src->mp_page, srcindx, key.mv_size);

	/* The key value just changed due to del_node, find it again.
	 */
	if (!IS_LEAF2(src->mp_page)) {
		srcnode = NODEPTR(src->mp_page, srcindx);
		key.mv_data = NODEKEY(srcnode);
	}

	/* Update the parent separators.
	 */
	if (srcindx == 0) {
		if (src->mp_pi != 0) {
			DPRINTF("update separator for source page %lu to [%s]",
				src->mp_page->mp_pgno, DKEY(&key));
			if ((rc = mdb_update_key(src->mp_parent, src->mp_pi,
				&key)) != MDB_SUCCESS)
				return rc;
		}
		if (IS_BRANCH(src->mp_page)) {
			MDB_val	 nullkey;
			nullkey.mv_size = 0;
			assert(mdb_update_key(src->mp_page, 0, &nullkey) == MDB_SUCCESS);
		}
	}

	if (dstindx == 0) {
		if (dst->mp_pi != 0) {
			DPRINTF("update separator for destination page %lu to [%s]",
				dst->mp_page->mp_pgno, DKEY(&key));
			if ((rc = mdb_update_key(dst->mp_parent, dst->mp_pi,
				&key)) != MDB_SUCCESS)
				return rc;
		}
		if (IS_BRANCH(dst->mp_page)) {
			MDB_val	 nullkey;
			nullkey.mv_size = 0;
			assert(mdb_update_key(dst->mp_page, 0, &nullkey) == MDB_SUCCESS);
		}
	}

	return MDB_SUCCESS;
}

static int
mdb_merge(MDB_txn *txn, MDB_dbi dbi, MDB_pageparent *src, MDB_pageparent *dst)
{
	int			 rc;
	indx_t			 i;
	MDB_node		*srcnode;
	MDB_val		 key, data;
	MDB_pageparent	mpp;
	MDB_dhead *dh;

	DPRINTF("merging page %lu and %lu", src->mp_page->mp_pgno, dst->mp_page->mp_pgno);

	assert(txn != NULL);
	assert(src->mp_parent);	/* can't merge root page */
	assert(dst->mp_parent);

	/* Mark src and dst as dirty. */
	if ((rc = mdb_touch(txn, dbi, src)) ||
	    (rc = mdb_touch(txn, dbi, dst)))
		return rc;

	/* Move all nodes from src to dst.
	 */
	if (IS_LEAF2(src->mp_page)) {
		key.mv_size = txn->mt_dbs[dbi].md_pad;
		key.mv_data = METADATA(src->mp_page);
		for (i = 0; i < NUMKEYS(src->mp_page); i++) {
			rc = mdb_add_node(txn, dbi, dst->mp_page, NUMKEYS(dst->mp_page), &key,
				NULL, 0, 0);
			if (rc != MDB_SUCCESS)
				return rc;
			key.mv_data = (char *)key.mv_data + key.mv_size;
		}
	} else {
		for (i = 0; i < NUMKEYS(src->mp_page); i++) {
			srcnode = NODEPTR(src->mp_page, i);

			key.mv_size = srcnode->mn_ksize;
			key.mv_data = NODEKEY(srcnode);
			data.mv_size = NODEDSZ(srcnode);
			data.mv_data = NODEDATA(srcnode);
			rc = mdb_add_node(txn, dbi, dst->mp_page, NUMKEYS(dst->mp_page), &key,
				&data, NODEPGNO(srcnode), srcnode->mn_flags);
			if (rc != MDB_SUCCESS)
				return rc;
		}
	}

	DPRINTF("dst page %lu now has %u keys (%.1f%% filled)",
	    dst->mp_page->mp_pgno, NUMKEYS(dst->mp_page), (float)PAGEFILL(txn->mt_env, dst->mp_page) / 10);

	/* Unlink the src page from parent.
	 */
	mdb_del_node(src->mp_parent, src->mp_pi, 0);
	if (src->mp_pi == 0) {
		key.mv_size = 0;
		if ((rc = mdb_update_key(src->mp_parent, 0, &key)) != MDB_SUCCESS)
			return rc;
	}

	if (IS_LEAF(src->mp_page))
		txn->mt_dbs[dbi].md_leaf_pages--;
	else
		txn->mt_dbs[dbi].md_branch_pages--;

	mpp.mp_page = src->mp_parent;
	dh = (MDB_dhead *)src->mp_parent;
	dh--;
	mpp.mp_parent = dh->md_parent;
	mpp.mp_pi = dh->md_pi;

	return mdb_rebalance(txn, dbi, &mpp);
}

#define FILL_THRESHOLD	 250

static int
mdb_rebalance(MDB_txn *txn, MDB_dbi dbi, MDB_pageparent *mpp)
{
	MDB_node	*node;
	MDB_page	*root;
	MDB_pageparent npp;
	indx_t		 si = 0, di = 0;
	int rc;

	assert(txn != NULL);
	assert(mpp != NULL);

	DPRINTF("rebalancing %s page %lu (has %u keys, %.1f%% full)",
	    IS_LEAF(mpp->mp_page) ? "leaf" : "branch",
	    mpp->mp_page->mp_pgno, NUMKEYS(mpp->mp_page), (float)PAGEFILL(txn->mt_env, mpp->mp_page) / 10);

	if (PAGEFILL(txn->mt_env, mpp->mp_page) >= FILL_THRESHOLD) {
		DPRINTF("no need to rebalance page %lu, above fill threshold",
		    mpp->mp_page->mp_pgno);
		return MDB_SUCCESS;
	}

	if (mpp->mp_parent == NULL) {
		if (NUMKEYS(mpp->mp_page) == 0) {
			DPUTS("tree is completely empty");
			txn->mt_dbs[dbi].md_root = P_INVALID;
			txn->mt_dbs[dbi].md_depth = 0;
			txn->mt_dbs[dbi].md_leaf_pages = 0;
			mdb_midl_append(txn->mt_free_pgs, mpp->mp_page->mp_pgno);
		} else if (IS_BRANCH(mpp->mp_page) && NUMKEYS(mpp->mp_page) == 1) {
			DPUTS("collapsing root page!");
			mdb_midl_append(txn->mt_free_pgs, mpp->mp_page->mp_pgno);
			txn->mt_dbs[dbi].md_root = NODEPGNO(NODEPTR(mpp->mp_page, 0));
			if ((rc = mdb_get_page(txn, txn->mt_dbs[dbi].md_root, &root)))
				return rc;
			txn->mt_dbs[dbi].md_depth--;
			txn->mt_dbs[dbi].md_branch_pages--;
		} else
			DPUTS("root page doesn't need rebalancing");
		return MDB_SUCCESS;
	}

	/* The parent (branch page) must have at least 2 pointers,
	 * otherwise the tree is invalid.
	 */
	assert(NUMKEYS(mpp->mp_parent) > 1);

	/* Leaf page fill factor is below the threshold.
	 * Try to move keys from left or right neighbor, or
	 * merge with a neighbor page.
	 */

	/* Find neighbors.
	 */
	if (mpp->mp_pi == 0) {
		/* We're the leftmost leaf in our parent.
		 */
		DPUTS("reading right neighbor");
		node = NODEPTR(mpp->mp_parent, mpp->mp_pi + 1);
		if ((rc = mdb_get_page(txn, NODEPGNO(node), &npp.mp_page)))
			return rc;
		npp.mp_pi = mpp->mp_pi + 1;
		si = 0;
		di = NUMKEYS(mpp->mp_page);
	} else {
		/* There is at least one neighbor to the left.
		 */
		DPUTS("reading left neighbor");
		node = NODEPTR(mpp->mp_parent, mpp->mp_pi - 1);
		if ((rc = mdb_get_page(txn, NODEPGNO(node), &npp.mp_page)))
			return rc;
		npp.mp_pi = mpp->mp_pi - 1;
		si = NUMKEYS(npp.mp_page) - 1;
		di = 0;
	}
	npp.mp_parent = mpp->mp_parent;

	DPRINTF("found neighbor page %lu (%u keys, %.1f%% full)",
	    npp.mp_page->mp_pgno, NUMKEYS(npp.mp_page), (float)PAGEFILL(txn->mt_env, npp.mp_page) / 10);

	/* If the neighbor page is above threshold and has at least two
	 * keys, move one key from it.
	 *
	 * Otherwise we should try to merge them.
	 */
	if (PAGEFILL(txn->mt_env, npp.mp_page) >= FILL_THRESHOLD && NUMKEYS(npp.mp_page) >= 2)
		return mdb_move_node(txn, dbi, &npp, si, mpp, di);
	else { /* FIXME: if (has_enough_room()) */
		if (mpp->mp_pi == 0)
			return mdb_merge(txn, dbi, &npp, mpp);
		else
			return mdb_merge(txn, dbi, mpp, &npp);
	}
}

static int
mdb_del0(MDB_cursor *mc, unsigned int ki, MDB_pageparent *mpp, MDB_node *leaf)
{
	int rc;

	/* add overflow pages to free list */
	if (!IS_LEAF2(mpp->mp_page) && F_ISSET(leaf->mn_flags, F_BIGDATA)) {
		int i, ovpages;
		pgno_t pg;

		memcpy(&pg, NODEDATA(leaf), sizeof(pg));
		ovpages = OVPAGES(NODEDSZ(leaf), mc->mc_txn->mt_env->me_psize);
		for (i=0; i<ovpages; i++) {
			DPRINTF("freed ov page %lu", pg);
			mdb_midl_append(mc->mc_txn->mt_free_pgs, pg);
			pg++;
		}
	}
	mdb_del_node(mpp->mp_page, ki, mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad);
	mc->mc_txn->mt_dbs[mc->mc_dbi].md_entries--;
	rc = mdb_rebalance(mc->mc_txn, mc->mc_dbi, mpp);
	if (rc != MDB_SUCCESS)
		mc->mc_txn->mt_flags |= MDB_TXN_ERROR;

	return rc;
}

int
mdb_del(MDB_txn *txn, MDB_dbi dbi,
    MDB_val *key, MDB_val *data)
{
	MDB_cursor mc;
	MDB_xcursor mx;
	MDB_cursor_op op;
	MDB_val rdata, *xdata;
	int		 rc, exact;
	DKBUF;

	assert(key != NULL);

	DPRINTF("====> delete db %u key [%s]", dbi, DKEY(key));

	if (txn == NULL || !dbi || dbi >= txn->mt_numdbs)
		return EINVAL;

	if (F_ISSET(txn->mt_flags, MDB_TXN_RDONLY)) {
		return EACCES;
	}

	if (key->mv_size == 0 || key->mv_size > MAXKEYSIZE) {
		return EINVAL;
	}

	mc.mc_txn = txn;
	mc.mc_dbi = dbi;
	mc.mc_flags = 0;
	if (txn->mt_dbs[dbi].md_flags & MDB_DUPSORT) {
		mc.mc_xcursor = &mx;
		mdb_xcursor_init0(&mc);
	} else {
		mc.mc_xcursor = NULL;
	}

	exact = 0;
	if (data) {
		op = MDB_GET_BOTH;
		rdata = *data;
		xdata = &rdata;
	} else {
		op = MDB_SET;
		xdata = NULL;
	}
	rc = mdb_cursor_set(&mc, key, xdata, op, &exact);
	if (rc == 0)
		rc = mdb_cursor_del(&mc, data ? 0 : MDB_NODUPDATA);
	return rc;
}

/* Split page <*mpp>, and insert <key,(data|newpgno)> in either left or
 * right sibling, at index <*newindxp> (as if unsplit). Updates *mpp and
 * *newindxp with the actual values after split, ie if *mpp and *newindxp
 * refer to a node in the new right sibling page.
 */
static int
mdb_split(MDB_txn *txn, MDB_dbi dbi, MDB_page **mpp, unsigned int *newindxp,
    MDB_val *newkey, MDB_val *newdata, pgno_t newpgno)
{
	uint8_t		 flags;
	int		 rc = MDB_SUCCESS, ins_new = 0;
	indx_t		 newindx;
	pgno_t		 pgno = 0;
	unsigned int	 i, j, split_indx, nkeys, pmax;
	MDB_node	*node;
	MDB_val	 sepkey, rkey, rdata;
	MDB_page	*copy, *cptr;
	MDB_dpage	*mdp, *rdp, *pdp;
	MDB_dhead *dh;
	DKBUF;

	assert(txn != NULL);

	dh = ((MDB_dhead *)*mpp) - 1;
	mdp = (MDB_dpage *)dh;
	newindx = *newindxp;

	DPRINTF("-----> splitting %s page %lu and adding [%s] at index %i",
	    IS_LEAF(&mdp->p) ? "leaf" : "branch", mdp->p.mp_pgno,
	    DKEY(newkey), *newindxp);

	if (mdp->h.md_parent == NULL) {
		if ((pdp = mdb_new_page(txn, dbi, P_BRANCH, 1)) == NULL)
			return ENOMEM;
		mdp->h.md_pi = 0;
		mdp->h.md_parent = &pdp->p;
		txn->mt_dbs[dbi].md_root = pdp->p.mp_pgno;
		DPRINTF("root split! new root = %lu", pdp->p.mp_pgno);
		txn->mt_dbs[dbi].md_depth++;

		/* Add left (implicit) pointer. */
		if ((rc = mdb_add_node(txn, dbi, &pdp->p, 0, NULL, NULL,
		    mdp->p.mp_pgno, 0)) != MDB_SUCCESS)
			return rc;
	} else {
		DPRINTF("parent branch page is %lu", mdp->h.md_parent->mp_pgno);
	}

	/* Create a right sibling. */
	if ((rdp = mdb_new_page(txn, dbi, mdp->p.mp_flags, 1)) == NULL)
		return ENOMEM;
	rdp->h.md_parent = mdp->h.md_parent;
	rdp->h.md_pi = mdp->h.md_pi + 1;
	DPRINTF("new right sibling: page %lu", rdp->p.mp_pgno);

	nkeys = NUMKEYS(&mdp->p);
	split_indx = nkeys / 2 + 1;

	if (IS_LEAF2(&rdp->p)) {
		char *split, *ins;
		int x;
		unsigned int lsize, rsize, ksize;
		/* Move half of the keys to the right sibling */
		copy = NULL;
		x = *newindxp - split_indx;
		ksize = txn->mt_dbs[dbi].md_pad;
		split = LEAF2KEY(&mdp->p, split_indx, ksize);
		rsize = (nkeys - split_indx) * ksize;
		lsize = (nkeys - split_indx) * sizeof(indx_t);
		mdp->p.mp_lower -= lsize;
		rdp->p.mp_lower += lsize;
		mdp->p.mp_upper += rsize - lsize;
		rdp->p.mp_upper -= rsize - lsize;
		sepkey.mv_size = ksize;
		if (newindx == split_indx) {
			sepkey.mv_data = newkey->mv_data;
		} else {
			sepkey.mv_data = split;
		}
		if (x<0) {
			ins = LEAF2KEY(&mdp->p, *newindxp, ksize);
			memcpy(&rdp->p.mp_ptrs, split, rsize);
			sepkey.mv_data = &rdp->p.mp_ptrs;
			memmove(ins+ksize, ins, (split_indx - *newindxp) * ksize);
			memcpy(ins, newkey->mv_data, ksize);
			mdp->p.mp_lower += sizeof(indx_t);
			mdp->p.mp_upper -= ksize - sizeof(indx_t);
		} else {
			if (x)
				memcpy(&rdp->p.mp_ptrs, split, x * ksize);
			ins = LEAF2KEY(&rdp->p, x, ksize);
			memcpy(ins, newkey->mv_data, ksize);
			memcpy(ins+ksize, split + x * ksize, rsize - x * ksize);
			rdp->p.mp_lower += sizeof(indx_t);
			rdp->p.mp_upper -= ksize - sizeof(indx_t);
			*newindxp = x;
			*mpp = &rdp->p;
		}
		goto newsep;
	}

	/* For leaf pages, check the split point based on what
	 * fits where, since otherwise add_node can fail.
	 */
	if (IS_LEAF(&mdp->p)) {
		unsigned int psize, nsize;
		/* Maximum free space in an empty page */
		pmax = txn->mt_env->me_psize - PAGEHDRSZ;
		nsize = mdb_leaf_size(txn->mt_env, newkey, newdata);
		if (newindx < split_indx) {
			psize = nsize;
			for (i=0; i<split_indx; i++) {
				node = NODEPTR(&mdp->p, i);
				psize += NODESIZE + NODEKSZ(node) + sizeof(indx_t);
				if (F_ISSET(node->mn_flags, F_BIGDATA))
					psize += sizeof(pgno_t);
				else
					psize += NODEDSZ(node);
				if (psize > pmax) {
					split_indx = i;
					break;
				}
			}
		} else {
			psize = nsize;
			for (i=nkeys-1; i>=split_indx; i--) {
				node = NODEPTR(&mdp->p, i);
				psize += NODESIZE + NODEKSZ(node) + sizeof(indx_t);
				if (F_ISSET(node->mn_flags, F_BIGDATA))
					psize += sizeof(pgno_t);
				else
					psize += NODEDSZ(node);
				if (psize > pmax) {
					split_indx = i+1;
					break;
				}
			}
		}
	}

	/* First find the separating key between the split pages.
	 */
	if (newindx == split_indx) {
		sepkey.mv_size = newkey->mv_size;
		sepkey.mv_data = newkey->mv_data;
	} else {
		node = NODEPTR(&mdp->p, split_indx);
		sepkey.mv_size = node->mn_ksize;
		sepkey.mv_data = NODEKEY(node);
	}

newsep:
	DPRINTF("separator is [%s]", DKEY(&sepkey));

	/* Copy separator key to the parent.
	 */
	if (SIZELEFT(rdp->h.md_parent) < mdb_branch_size(txn->mt_env, &sepkey)) {
		rc = mdb_split(txn, dbi, &rdp->h.md_parent, &rdp->h.md_pi,
		    &sepkey, NULL, rdp->p.mp_pgno);

		/* Right page might now have changed parent.
		 * Check if left page also changed parent.
		 */
		if (rdp->h.md_parent != mdp->h.md_parent &&
		    mdp->h.md_pi >= NUMKEYS(mdp->h.md_parent)) {
			mdp->h.md_parent = rdp->h.md_parent;
			mdp->h.md_pi = rdp->h.md_pi - 1;
		}
	} else {
		rc = mdb_add_node(txn, dbi, rdp->h.md_parent, rdp->h.md_pi,
		    &sepkey, NULL, rdp->p.mp_pgno, 0);
	}
	if (IS_LEAF2(&rdp->p)) {
		return rc;
	}
	if (rc != MDB_SUCCESS) {
		return rc;
	}

	/* Move half of the keys to the right sibling. */
	if ((copy = malloc(txn->mt_env->me_psize)) == NULL)
		return ENOMEM;

	copy->mp_pgno  = mdp->p.mp_pgno;
	copy->mp_flags = mdp->p.mp_flags;
	copy->mp_lower = PAGEHDRSZ;
	copy->mp_upper = txn->mt_env->me_psize;
	cptr = copy;
	for (i = j = 0; i <= nkeys; j++) {
		if (i == split_indx) {
		/* Insert in right sibling. */
		/* Reset insert index for right sibling. */
			j = (i == newindx && ins_new);
			cptr = &rdp->p;
		}

		if (i == newindx && !ins_new) {
			/* Insert the original entry that caused the split. */
			rkey.mv_data = newkey->mv_data;
			rkey.mv_size = newkey->mv_size;
			if (IS_LEAF(&mdp->p)) {
				rdata.mv_data = newdata->mv_data;
				rdata.mv_size = newdata->mv_size;
			} else
				pgno = newpgno;
			flags = 0;

			ins_new = 1;

			/* Update page and index for the new key. */
			*newindxp = j;
			if (cptr == &rdp->p)
				*mpp = cptr;
		} else if (i == nkeys) {
			break;
		} else {
			node = NODEPTR(&mdp->p, i);
			rkey.mv_data = NODEKEY(node);
			rkey.mv_size = node->mn_ksize;
			if (IS_LEAF(&mdp->p)) {
				rdata.mv_data = NODEDATA(node);
				rdata.mv_size = node->mn_dsize;
			} else
				pgno = NODEPGNO(node);
			flags = node->mn_flags;

			i++;
		}

		if (!IS_LEAF(&mdp->p) && j == 0) {
			/* First branch index doesn't need key data. */
			rkey.mv_size = 0;
		}

		rc = mdb_add_node(txn, dbi, cptr, j, &rkey, &rdata, pgno, flags);
	}
	nkeys = NUMKEYS(copy);
	for (i=0; i<nkeys; i++)
		mdp->p.mp_ptrs[i] = copy->mp_ptrs[i];
	mdp->p.mp_lower = copy->mp_lower;
	mdp->p.mp_upper = copy->mp_upper;
	memcpy(NODEPTR(&mdp->p, nkeys-1), NODEPTR(copy, nkeys-1),
		txn->mt_env->me_psize - copy->mp_upper);

	free(copy);
	return rc;
}

#if 0
static int
mdb_put0(MDB_txn *txn, MDB_dbi dbi,
    MDB_val *key, MDB_val *data, unsigned int flags)
{
	int		 rc = MDB_SUCCESS, exact;
	unsigned int	 ki;
	MDB_node	*leaf;
	MDB_pageparent	mpp;
	MDB_val	xdata, *rdata, dkey;
	MDB_db dummy;
	char dbuf[PAGESIZE];
	int do_sub = 0;
	size_t nsize;
	DKBUF;

	DPRINTF("==> put db %u key [%s], size %zu, data size %zu",
		dbi, DKEY(key), key->mv_size, data->mv_size);

	dkey.mv_size = 0;
	mpp.mp_parent = NULL;
	mpp.mp_pi = 0;
	rc = mdb_search_page(txn, dbi, key, NULL, 1, &mpp);
	if (rc == MDB_SUCCESS) {
		leaf = mdb_search_node(txn, dbi, mpp.mp_page, key, &exact, &ki);
		if (leaf && exact) {
			if (flags == MDB_NOOVERWRITE) {
				DPRINTF("duplicate key [%s]", DKEY(key));
				return MDB_KEYEXIST;
			}
			/* there's only a key anyway, so this is a no-op */
			if (IS_LEAF2(mpp.mp_page))
				return MDB_SUCCESS;

			if (F_ISSET(txn->mt_dbs[dbi].md_flags, MDB_DUPSORT)) {
				/* Was a single item before, must convert now */
				if (!F_ISSET(leaf->mn_flags, F_DUPDATA)) {
					dkey.mv_size = NODEDSZ(leaf);
					dkey.mv_data = dbuf;
					memcpy(dbuf, NODEDATA(leaf), dkey.mv_size);
					/* data matches, ignore it */
					if (!mdb_dcmp(txn, dbi, data, &dkey))
						return (flags == MDB_NODUPDATA) ? MDB_KEYEXIST : MDB_SUCCESS;
					memset(&dummy, 0, sizeof(dummy));
					if (txn->mt_dbs[dbi].md_flags & MDB_DUPFIXED) {
						dummy.md_pad = data->mv_size;
						dummy.md_flags = MDB_DUPFIXED;
						if (txn->mt_dbs[dbi].md_flags & MDB_INTEGERDUP)
							dummy.md_flags |= MDB_INTEGERKEY;
					}
					dummy.md_root = P_INVALID;
					if (dkey.mv_size == sizeof(MDB_db)) {
						memcpy(NODEDATA(leaf), &dummy, sizeof(dummy));
						goto put_sub;
					}
					mdb_del_node(mpp.mp_page, ki, 0);
					do_sub = 1;
					rdata = &xdata;
					xdata.mv_size = sizeof(MDB_db);
					xdata.mv_data = &dummy;
					goto new_sub;
				}
				goto put_sub;
			}
			/* same size, just replace it */
			if (!F_ISSET(leaf->mn_flags, F_BIGDATA) &&
				NODEDSZ(leaf) == data->mv_size) {
				memcpy(NODEDATA(leaf), data->mv_data, data->mv_size);
				goto done;
			}
			mdb_del_node(mpp.mp_page, ki, 0);
		}
		if (leaf == NULL) {		/* append if not found */
			ki = NUMKEYS(mpp.mp_page);
			DPRINTF("appending key at index %i", ki);
		}
	} else if (rc == MDB_NOTFOUND) {
		MDB_dpage *dp;
		/* new file, just write a root leaf page */
		DPUTS("allocating new root leaf page");
		if ((dp = mdb_new_page(txn, dbi, P_LEAF, 1)) == NULL) {
			return ENOMEM;
		}
		mpp.mp_page = &dp->p;
		txn->mt_dbs[dbi].md_root = mpp.mp_page->mp_pgno;
		txn->mt_dbs[dbi].md_depth++;
		txn->mt_dbxs[dbi].md_dirty = 1;
		if ((txn->mt_dbs[dbi].md_flags & (MDB_DUPSORT|MDB_DUPFIXED)) == MDB_DUPFIXED)
			mpp.mp_page->mp_flags |= P_LEAF2;
		ki = 0;
	}
	else
		goto done;

	assert(IS_LEAF(mpp.mp_page));
	DPRINTF("there are %u keys, should insert new key at index %i",
		NUMKEYS(mpp.mp_page), ki);

	rdata = data;

new_sub:
	nsize = IS_LEAF2(mpp.mp_page) ? key->mv_size : mdb_leaf_size(txn->mt_env, key, rdata);
	if (SIZELEFT(mpp.mp_page) < nsize) {
		rc = mdb_split(txn, dbi, &mpp.mp_page, &ki, key, rdata, P_INVALID);
	} else {
		/* There is room already in this leaf page. */
		rc = mdb_add_node(txn, dbi, mpp.mp_page, ki, key, rdata, 0, 0);
	}

	if (rc != MDB_SUCCESS)
		txn->mt_flags |= MDB_TXN_ERROR;
	else {
		/* Remember if we just added a subdatabase */
		if (flags & F_SUBDATA) {
			leaf = NODEPTR(mpp.mp_page, ki);
			leaf->mn_flags |= F_SUBDATA;
		}

		/* Now store the actual data in the child DB. Note that we're
		 * storing the user data in the keys field, so there are strict
		 * size limits on dupdata. The actual data fields of the child
		 * DB are all zero size.
		 */
		if (do_sub) {
			MDB_cursor mc;
			MDB_xcursor mx;

			leaf = NODEPTR(mpp.mp_page, ki);
put_sub:
			mc.mc_txn = txn;
			mc.mc_dbi = dbi;
			mc.mc_flags = 0;
			mc.mc_xcursor = &mx;
			mdb_xcursor_init0(&mc);
			mdb_xcursor_init1(txn, dbi, &mx, mpp.mp_page, leaf);
			xdata.mv_size = 0;
			xdata.mv_data = "";
			if (flags == MDB_NODUPDATA)
				flags = MDB_NOOVERWRITE;
			/* converted, write the original data first */
			if (dkey.mv_size) {
				rc = mdb_put0(&mx.mx_txn, mx.mx_cursor.mc_dbi, &dkey, &xdata, flags);
				if (rc) return rc;
				leaf->mn_flags |= F_DUPDATA;
			}
			rc = mdb_put0(&mx.mx_txn, mx.mx_cursor.mc_dbi, data, &xdata, flags);
			mdb_xcursor_fini(&mc);
			memcpy(NODEDATA(leaf), &mx.mx_txn.mt_dbs[mx.mx_cursor.mc_dbi],
				sizeof(MDB_db));
		}
		txn->mt_dbs[dbi].md_entries++;
	}

done:
	return rc;
}
#endif

int
mdb_put(MDB_txn *txn, MDB_dbi dbi,
    MDB_val *key, MDB_val *data, unsigned int flags)
{
	MDB_cursor mc;
	MDB_xcursor mx;

	assert(key != NULL);
	assert(data != NULL);

	if (txn == NULL || !dbi || dbi >= txn->mt_numdbs)
		return EINVAL;

	if (F_ISSET(txn->mt_flags, MDB_TXN_RDONLY)) {
		return EACCES;
	}

	if (key->mv_size == 0 || key->mv_size > MAXKEYSIZE) {
		return EINVAL;
	}

	if ((flags & (MDB_NOOVERWRITE|MDB_NODUPDATA)) != flags)
		return EINVAL;

	mc.mc_txn = txn;
	mc.mc_dbi = dbi;
	mc.mc_snum = 0;
	mc.mc_flags = 0;
	if (txn->mt_dbs[dbi].md_flags & MDB_DUPSORT) {
		mc.mc_xcursor = &mx;
		mdb_xcursor_init0(&mc);
	} else {
		mc.mc_xcursor = NULL;
	}
	return mdb_cursor_put(&mc, key, data, flags);
}

int
mdb_env_set_flags(MDB_env *env, unsigned int flag, int onoff)
{
#define	CHANGEABLE	(MDB_NOSYNC)
	if ((flag & CHANGEABLE) != flag)
		return EINVAL;
	if (onoff)
		env->me_flags |= flag;
	else
		env->me_flags &= ~flag;
	return MDB_SUCCESS;
}

int
mdb_env_get_flags(MDB_env *env, unsigned int *arg)
{
	if (!env || !arg)
		return EINVAL;

	*arg = env->me_flags;
	return MDB_SUCCESS;
}

int
mdb_env_get_path(MDB_env *env, const char **arg)
{
	if (!env || !arg)
		return EINVAL;

	*arg = env->me_path;
	return MDB_SUCCESS;
}

static int
mdb_stat0(MDB_env *env, MDB_db *db, MDB_stat *arg)
{
	arg->ms_psize = env->me_psize;
	arg->ms_depth = db->md_depth;
	arg->ms_branch_pages = db->md_branch_pages;
	arg->ms_leaf_pages = db->md_leaf_pages;
	arg->ms_overflow_pages = db->md_overflow_pages;
	arg->ms_entries = db->md_entries;

	return MDB_SUCCESS;
}
int
mdb_env_stat(MDB_env *env, MDB_stat *arg)
{
	int toggle;

	if (env == NULL || arg == NULL)
		return EINVAL;

	mdb_env_read_meta(env, &toggle);

	return mdb_stat0(env, &env->me_metas[toggle]->mm_dbs[MAIN_DBI], arg);
}

static void
mdb_default_cmp(MDB_txn *txn, MDB_dbi dbi)
{
	if (txn->mt_dbs[dbi].md_flags & (MDB_REVERSEKEY
#if __BYTE_ORDER == __LITTLE_ENDIAN
		|MDB_INTEGERKEY
#endif
	))
		txn->mt_dbxs[dbi].md_cmp = memnrcmp;
	else
		txn->mt_dbxs[dbi].md_cmp = memncmp;

	if (txn->mt_dbs[dbi].md_flags & MDB_DUPSORT) {
		if (txn->mt_dbs[dbi].md_flags & MDB_INTEGERDUP) {
			if (txn->mt_dbs[dbi].md_flags & MDB_DUPFIXED)
				txn->mt_dbxs[dbi].md_dcmp = intcmp;
			else
#if __BYTE_ORDER == __LITTLE_ENDIAN
				txn->mt_dbxs[dbi].md_dcmp = memnrcmp;
#else
				txn->mt_dbxs[dbi].md_dcmp = memncmp;
#endif
		} else if (txn->mt_dbs[dbi].md_flags & MDB_REVERSEDUP) {
			txn->mt_dbxs[dbi].md_dcmp = memnrcmp;
		} else {
			txn->mt_dbxs[dbi].md_dcmp = memncmp;
		}
	} else {
		txn->mt_dbxs[dbi].md_dcmp = NULL;
	}
}

int mdb_open(MDB_txn *txn, const char *name, unsigned int flags, MDB_dbi *dbi)
{
	MDB_val key, data;
	MDB_dbi i;
	int rc, dirty = 0;
	size_t len;

	if (txn->mt_dbxs[FREE_DBI].md_cmp == NULL) {
		mdb_default_cmp(txn, FREE_DBI);
	}

	/* main DB? */
	if (!name) {
		*dbi = MAIN_DBI;
		if (flags & (MDB_DUPSORT|MDB_REVERSEKEY|MDB_INTEGERKEY))
			txn->mt_dbs[MAIN_DBI].md_flags |= (flags & (MDB_DUPSORT|MDB_REVERSEKEY|MDB_INTEGERKEY));
		mdb_default_cmp(txn, MAIN_DBI);
		return MDB_SUCCESS;
	}

	if (txn->mt_dbxs[MAIN_DBI].md_cmp == NULL) {
		mdb_default_cmp(txn, MAIN_DBI);
	}

	/* Is the DB already open? */
	len = strlen(name);
	for (i=2; i<txn->mt_numdbs; i++) {
		if (len == txn->mt_dbxs[i].md_name.mv_size &&
			!strncmp(name, txn->mt_dbxs[i].md_name.mv_data, len)) {
			*dbi = i;
			return MDB_SUCCESS;
		}
	}

	if (txn->mt_numdbs >= txn->mt_env->me_maxdbs - 1)
		return ENFILE;

	/* Find the DB info */
	key.mv_size = len;
	key.mv_data = (void *)name;
	rc = mdb_get(txn, MAIN_DBI, &key, &data);

	/* Create if requested */
	if (rc == MDB_NOTFOUND && (flags & MDB_CREATE)) {
		MDB_cursor mc;
		MDB_db dummy;
		data.mv_size = sizeof(MDB_db);
		data.mv_data = &dummy;
		memset(&dummy, 0, sizeof(dummy));
		dummy.md_root = P_INVALID;
		dummy.md_flags = flags & 0xffff;
		mc.mc_txn = txn;
		mc.mc_dbi = MAIN_DBI;
		mc.mc_flags = 0;
		rc = mdb_cursor_put(&mc, &key, &data, F_SUBDATA);
		dirty = 1;
	}

	/* OK, got info, add to table */
	if (rc == MDB_SUCCESS) {
		txn->mt_dbxs[txn->mt_numdbs].md_name.mv_data = strdup(name);
		txn->mt_dbxs[txn->mt_numdbs].md_name.mv_size = len;
		txn->mt_dbxs[txn->mt_numdbs].md_rel = NULL;
		txn->mt_dbxs[txn->mt_numdbs].md_parent = MAIN_DBI;
		txn->mt_dbxs[txn->mt_numdbs].md_dirty = dirty;
		memcpy(&txn->mt_dbs[txn->mt_numdbs], data.mv_data, sizeof(MDB_db));
		*dbi = txn->mt_numdbs;
		txn->mt_env->me_dbs[0][txn->mt_numdbs] = txn->mt_dbs[txn->mt_numdbs];
		txn->mt_env->me_dbs[1][txn->mt_numdbs] = txn->mt_dbs[txn->mt_numdbs];
		mdb_default_cmp(txn, txn->mt_numdbs);
		txn->mt_numdbs++;
	}

	return rc;
}

int mdb_stat(MDB_txn *txn, MDB_dbi dbi, MDB_stat *arg)
{
	if (txn == NULL || arg == NULL || dbi >= txn->mt_numdbs)
		return EINVAL;

	return mdb_stat0(txn->mt_env, &txn->mt_dbs[dbi], arg);
}

void mdb_close(MDB_txn *txn, MDB_dbi dbi)
{
	char *ptr;
	if (dbi <= MAIN_DBI || dbi >= txn->mt_numdbs)
		return;
	ptr = txn->mt_dbxs[dbi].md_name.mv_data;
	txn->mt_dbxs[dbi].md_name.mv_data = NULL;
	txn->mt_dbxs[dbi].md_name.mv_size = 0;
	free(ptr);
}

int mdb_set_compare(MDB_txn *txn, MDB_dbi dbi, MDB_cmp_func *cmp)
{
	if (txn == NULL || !dbi || dbi >= txn->mt_numdbs)
		return EINVAL;

	txn->mt_dbxs[dbi].md_cmp = cmp;
	return MDB_SUCCESS;
}

int mdb_set_dupsort(MDB_txn *txn, MDB_dbi dbi, MDB_cmp_func *cmp)
{
	if (txn == NULL || !dbi || dbi >= txn->mt_numdbs)
		return EINVAL;

	txn->mt_dbxs[dbi].md_dcmp = cmp;
	return MDB_SUCCESS;
}

int mdb_set_relfunc(MDB_txn *txn, MDB_dbi dbi, MDB_rel_func *rel)
{
	if (txn == NULL || !dbi || dbi >= txn->mt_numdbs)
		return EINVAL;

	txn->mt_dbxs[dbi].md_rel = rel;
	return MDB_SUCCESS;
}

/** @} */
