#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/mman.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#include <fcntl.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "mdb.h"

#define ULONG		unsigned long
typedef ULONG		pgno_t;

#include "idl.h"

#ifndef DEBUG
#define DEBUG 1
#endif

#if (DEBUG +0) && defined(__GNUC__)
# define DPRINTF(fmt, ...) \
	fprintf(stderr, "%s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#else
# define DPRINTF(...)	((void) 0)
#endif

#define PAGESIZE	 4096
#define MDB_MINKEYS	 4
#define MDB_MAGIC	 0xBEEFC0DE
#define MDB_VERSION	 1
#define MAXKEYSIZE	 255

#define P_INVALID	 (~0UL)

#define F_ISSET(w, f)	 (((w) & (f)) == (f))

typedef uint16_t	 indx_t;

#define DEFAULT_READERS	126
#define DEFAULT_MAPSIZE	1048576

/* Lock descriptor stuff */
#define RXBODY	\
	ULONG		mr_txnid; \
	pid_t		mr_pid; \
	pthread_t	mr_tid
typedef struct MDB_rxbody {
	RXBODY;
} MDB_rxbody;

#ifndef CACHELINE
#define CACHELINE	64	/* most CPUs. Itanium uses 128 */
#endif

typedef struct MDB_reader {
	RXBODY;
	/* cache line alignment */
	char pad[CACHELINE-sizeof(MDB_rxbody)];
} MDB_reader;

#define	TXBODY \
	uint32_t	mt_magic;	\
	uint32_t	mt_version;	\
	pthread_mutex_t	mt_mutex;	\
	ULONG		mt_txnid;	\
	uint32_t	mt_numreaders
typedef struct MDB_txbody {
	TXBODY;
} MDB_txbody;

typedef struct MDB_txninfo {
	TXBODY;
	char pad[CACHELINE-sizeof(MDB_txbody)];
	pthread_mutex_t	mt_wmutex;
	char pad2[CACHELINE-sizeof(pthread_mutex_t)];
	MDB_reader	mt_readers[1];
} MDB_txninfo;

/* Common header for all page types. Overflow pages
 * occupy a number of contiguous pages with no
 * headers on any page after the first.
 */
typedef struct MDB_page {		/* represents a page of storage */
	pgno_t		mp_pgno;		/* page number */
#define	P_BRANCH	 0x01		/* branch page */
#define	P_LEAF		 0x02		/* leaf page */
#define	P_OVERFLOW	 0x04		/* overflow page */
#define	P_META		 0x08		/* meta page */
#define	P_DIRTY		 0x10		/* dirty page */
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
#define PAGEFILL(env, p) (1000L * ((env)->me_meta.mm_psize - PAGEHDRSZ - SIZELEFT(p)) / \
				((env)->me_meta.mm_psize - PAGEHDRSZ))
#define IS_LEAF(p)	 F_ISSET((p)->mp_flags, P_LEAF)
#define IS_BRANCH(p)	 F_ISSET((p)->mp_flags, P_BRANCH)
#define IS_OVERFLOW(p)	 F_ISSET((p)->mp_flags, P_OVERFLOW)

#define OVPAGES(size, psize)	(PAGEHDRSZ + size + psize - 1) / psize;

typedef struct MDB_meta {			/* meta (footer) page content */
	uint32_t	mm_magic;
	uint32_t	mm_version;
	void		*mm_address;		/* address for fixed mapping */
	size_t		mm_mapsize;			/* size of mmap region */
	pgno_t		mm_last_pg;			/* last used page in file */
	ULONG		mm_txnid;			/* txnid that committed this page */
	uint32_t	mm_psize;
	uint16_t	mm_flags;
	uint16_t	mm_depth;
	ULONG		mm_branch_pages;
	ULONG		mm_leaf_pages;
	ULONG		mm_overflow_pages;
	ULONG		mm_entries;
	pgno_t		mm_root;
} MDB_meta;

typedef struct MDB_dhead {					/* a dirty page */
	SIMPLEQ_ENTRY(MDB_dpage)	 md_next;	/* queue of dirty pages */
	MDB_page	*md_parent;
	unsigned	md_pi;				/* parent index */
	int			md_num;
} MDB_dhead;

typedef struct MDB_dpage {
	MDB_dhead	h;
	MDB_page	p;
} MDB_dpage;

SIMPLEQ_HEAD(dirty_queue, MDB_dpage);

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

static MDB_dpage *mdb_alloc_page(MDB_txn *txn, MDB_page *parent, unsigned int parent_idx, int num);
static int 		mdb_touch(MDB_txn *txn, MDB_pageparent *mp);

typedef struct MDB_ppage {					/* ordered list of pages */
	SLIST_ENTRY(MDB_ppage)	 mp_entry;
	MDB_page		*mp_page;
	unsigned int	mp_ki;		/* cursor index on page */
} MDB_ppage;
SLIST_HEAD(page_stack, MDB_ppage);

#define CURSOR_EMPTY(c)		 SLIST_EMPTY(&(c)->mc_stack)
#define CURSOR_TOP(c)		 SLIST_FIRST(&(c)->mc_stack)
#define CURSOR_POP(c)		 SLIST_REMOVE_HEAD(&(c)->mc_stack, mp_entry)
#define CURSOR_PUSH(c,p)	 SLIST_INSERT_HEAD(&(c)->mc_stack, p, mp_entry)

struct MDB_cursor {
	MDB_txn		*mc_txn;
	struct page_stack	 mc_stack;		/* stack of parent pages */
	MDB_dbi		mc_dbi;
	short		mc_initialized;	/* 1 if initialized */
	short		mc_eof;		/* 1 if end is reached */
};

#define METAHASHLEN	 offsetof(MDB_meta, mm_hash)
#define METADATA(p)	 ((void *)((char *)p + PAGEHDRSZ))

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
	char		mn_data[1];
} MDB_node;

typedef struct MDB_dbx {
	char		*md_name;
	MDB_cmp_func	*md_cmp;		/* user compare function */
	MDB_rel_func	*md_rel;		/* user relocate function */
} MDB_dbx;

typedef struct MDB_db {
	uint32_t	md_pad;
	uint16_t	md_flags;
	uint16_t	md_depth;
	ULONG		md_branch_pages;
	ULONG		md_leaf_pages;
	ULONG		md_overflow_pages;
	ULONG		md_entries;
	pgno_t		md_root;
} MDB_db;

struct MDB_txn {
	pgno_t		mt_next_pgno;	/* next unallocated page */
	ULONG		mt_txnid;
	ULONG		mt_oldest;
	MDB_env		*mt_env;	
	pgno_t		*mt_free_pgs;	/* this is an IDL */
	union {
		struct dirty_queue	*dirty_queue;	/* modified pages */
		MDB_reader	*reader;
	} mt_u;
	MDB_dbx		*mt_dbxs;		/* array */
	MDB_db		**mt_dbs;		/* array of ptrs */
	MDB_db		mt_db0;			/* just for write txns */
	unsigned int	mt_numdbs;

#define MDB_TXN_RDONLY		 0x01		/* read-only transaction */
#define MDB_TXN_ERROR		 0x02		/* an error has occurred */
#define MDB_TXN_METOGGLE	0x04		/* used meta page 1 */
	unsigned int		 mt_flags;
};

struct MDB_env {
	int			me_fd;
	int			me_lfd;
	uint32_t	me_flags;
	unsigned int			me_maxreaders;
	char		*me_path;
	char		*me_map;
	MDB_txninfo	*me_txns;
	MDB_meta	me_meta;
	MDB_txn		*me_txn;		/* current write transaction */
	size_t		me_mapsize;
	off_t		me_size;		/* current file size */
	pthread_key_t	me_txkey;	/* thread-key for readers */
	MDB_oldpages *me_pghead;
	MDB_oldpages *me_pgtail;
	MDB_dbx		*me_dbxs;		/* array */
	MDB_db		**me_dbs;		/* array of ptrs */
	unsigned int	me_numdbs;
};

#define NODESIZE	 offsetof(MDB_node, mn_data)

#define INDXSIZE(k)	 (NODESIZE + ((k) == NULL ? 0 : (k)->mv_size))
#define LEAFSIZE(k, d)	 (NODESIZE + (k)->mv_size + (d)->mv_size)
#define NODEPTR(p, i)	 ((MDB_node *)((char *)(p) + (p)->mp_ptrs[i]))
#define NODEKEY(node)	 (void *)((node)->mn_data)
#define NODEDATA(node)	 (void *)((char *)(node)->mn_data + (node)->mn_ksize)
#define NODEPGNO(node)	 ((node)->mn_pgno)
#define NODEDSZ(node)	 ((node)->mn_dsize)

#define MDB_COMMIT_PAGES	 64	/* max number of pages to write in one commit */
#define MDB_MAXCACHE_DEF	 1024	/* max number of pages to keep in cache  */

static int  mdb_search_page_root(MDB_txn *txn,
			    MDB_dbi dbi, MDB_val *key,
			    MDB_cursor *cursor, int modify,
			    MDB_pageparent *mpp);
static int  mdb_search_page(MDB_txn *txn,
			    MDB_dbi dbi, MDB_val *key,
			    MDB_cursor *cursor, int modify,
			    MDB_pageparent *mpp);

static int  mdbenv_read_header(MDB_env *env);
static int  mdb_check_meta_page(MDB_page *p);
static int  mdbenv_read_meta(MDB_env *env, int *which);
static int  mdbenv_write_meta(MDB_txn *txn);
static MDB_page *mdbenv_get_page(MDB_env *env, pgno_t pgno);

static MDB_node *mdb_search_node(MDB_txn *txn, MDB_dbi dbi, MDB_page *mp,
			    MDB_val *key, int *exactp, unsigned int *kip);
static int  mdb_add_node(MDB_txn *txn, MDB_dbi dbi, MDB_page *mp,
			    indx_t indx, MDB_val *key, MDB_val *data,
			    pgno_t pgno, uint8_t flags);
static void mdb_del_node(MDB_page *mp, indx_t indx);
static int  mdb_read_data(MDB_env *env, MDB_node *leaf, MDB_val *data);

static int		 mdb_rebalance(MDB_txn *txn, MDB_dbi dbi, MDB_pageparent *mp);
static int		 mdb_update_key(MDB_page *mp, indx_t indx, MDB_val *key);
static int		 mdb_move_node(MDB_txn *txn, MDB_dbi dbi, 
				MDB_pageparent *src, indx_t srcindx,
				MDB_pageparent *dst, indx_t dstindx);
static int		 mdb_merge(MDB_txn *txn, MDB_dbi dbi, MDB_pageparent *src,
			    MDB_pageparent *dst);
static int		 mdb_split(MDB_txn *txn, MDB_dbi dbi, MDB_page **mpp,
			    unsigned int *newindxp, MDB_val *newkey,
			    MDB_val *newdata, pgno_t newpgno);
static MDB_dpage *mdb_new_page(MDB_txn *txn, MDB_dbi dbi, uint32_t flags, int num);

static void		 cursor_pop_page(MDB_cursor *cursor);
static MDB_ppage *cursor_push_page(MDB_cursor *cursor,
			    MDB_page *mp);

static int		 mdb_set_key(MDB_node *node, MDB_val *key);
static int		 mdb_sibling(MDB_cursor *cursor, int move_right);
static int		 mdb_cursor_next(MDB_cursor *cursor,
			    MDB_val *key, MDB_val *data);
static int		 mdb_cursor_set(MDB_cursor *cursor,
			    MDB_val *key, MDB_val *data, int *exactp);
static int		 mdb_cursor_first(MDB_cursor *cursor,
			    MDB_val *key, MDB_val *data);

static size_t		 mdb_leaf_size(MDB_env *env, MDB_val *key,
			    MDB_val *data);
static size_t		 mdb_branch_size(MDB_env *env, MDB_val *key);

static int		 memncmp(const void *s1, size_t n1,
				 const void *s2, size_t n2);
static int		 memnrcmp(const void *s1, size_t n1,
				  const void *s2, size_t n2);

static int
memncmp(const void *s1, size_t n1, const void *s2, size_t n2)
{
	int diff, len_diff = -1;

	if (n1 >= n2) {
		len_diff = (n1 > n2);
		n1 = n2;
	}
	diff = memcmp(s1, s2, n1);
	return diff ? diff : len_diff;
}

static int
memnrcmp(const void *s1, size_t n1, const void *s2, size_t n2)
{
	const unsigned char	*p1, *p2, *p1_lim;

	if (n2 == 0)
		return n1 != 0;
	if (n1 == 0)
		return -1;

	p1 = (const unsigned char *)s1 + n1 - 1;
	p2 = (const unsigned char *)s2 + n2 - 1;

	for (p1_lim = (n1 <= n2 ? s1 : s2);  *p1 == *p2;  p1--, p2--) {
		if (p1 == p1_lim)
			return (p1 != s1) ? (p1 != p2) : (p2 != s2) ? -1 : 0;
	}
	return *p1 - *p2;
}

int
mdb_cmp(MDB_txn *txn, MDB_dbi dbi, const MDB_val *a, const MDB_val *b)
{
	return txn->mt_dbxs[dbi].md_cmp(a, b);
}

static int
_mdb_cmp(MDB_txn *txn, MDB_dbi dbi, const MDB_val *key1, const MDB_val *key2)
{
	if (F_ISSET(txn->mt_dbs[dbi]->md_flags, MDB_REVERSEKEY))
		return memnrcmp(key1->mv_data, key1->mv_size, key2->mv_data, key2->mv_size);
	else
		return memncmp((char *)key1->mv_data, key1->mv_size, key2->mv_data, key2->mv_size);
}

/* Allocate new page(s) for writing */
static MDB_dpage *
mdb_alloc_page(MDB_txn *txn, MDB_page *parent, unsigned int parent_idx, int num)
{
	MDB_dpage *dp;
	pgno_t pgno = P_INVALID;

	if (txn->mt_env->me_pghead) {
		ULONG oldest = txn->mt_txnid - 2;
		unsigned int i;
		for (i=0; i<txn->mt_env->me_txns->mt_numreaders; i++) {
			if (txn->mt_env->me_txns->mt_readers[i].mr_txnid < oldest)
				oldest = txn->mt_env->me_txns->mt_readers[i].mr_txnid;
		}
		if (oldest > txn->mt_env->me_pghead->mo_txnid) {
			MDB_oldpages *mop = txn->mt_env->me_pghead;
			txn->mt_oldest = oldest;
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
					if (!txn->mt_env->me_pghead)
						txn->mt_env->me_pgtail = NULL;
					free(mop);
				}
			}
		}
	}

	if ((dp = malloc(txn->mt_env->me_meta.mm_psize * num + sizeof(MDB_dhead))) == NULL)
		return NULL;
	dp->h.md_num = num;
	dp->h.md_parent = parent;
	dp->h.md_pi = parent_idx;
	SIMPLEQ_INSERT_TAIL(txn->mt_u.dirty_queue, dp, h.md_next);
	if (pgno == P_INVALID) {
		dp->p.mp_pgno = txn->mt_next_pgno;
		txn->mt_next_pgno += num;
	} else {
		dp->p.mp_pgno = pgno;
	}

	return dp;
}

/* Touch a page: make it dirty and re-insert into tree with updated pgno.
 */
static int
mdb_touch(MDB_txn *txn, MDB_pageparent *pp)
{
	MDB_page *mp = pp->mp_page;
	pgno_t	pgno;
	assert(txn != NULL);
	assert(pp != NULL);

	if (!F_ISSET(mp->mp_flags, P_DIRTY)) {
		MDB_dpage *dp;
		if ((dp = mdb_alloc_page(txn, pp->mp_parent, pp->mp_pi, 1)) == NULL)
			return ENOMEM;
		DPRINTF("touched page %lu -> %lu", mp->mp_pgno, dp->p.mp_pgno);
		mdb_idl_insert(txn->mt_free_pgs, mp->mp_pgno);
		pgno = dp->p.mp_pgno;
		memcpy(&dp->p, mp, txn->mt_env->me_meta.mm_psize);
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
mdbenv_sync(MDB_env *env)
{
	int rc = 0;
	if (!F_ISSET(env->me_flags, MDB_NOSYNC)) {
		if (fsync(env->me_fd))
			rc = errno;
	}
	return rc;
}

#define DBX_CHUNK	16	/* space for 16 DBs at a time */

int
mdb_txn_begin(MDB_env *env, int rdonly, MDB_txn **ret)
{
	MDB_txn	*txn;
	int rc, toggle;

	if ((txn = calloc(1, sizeof(*txn))) == NULL) {
		DPRINTF("calloc: %s", strerror(errno));
		return ENOMEM;
	}

	if (rdonly) {
		txn->mt_flags |= MDB_TXN_RDONLY;
	} else {
		txn->mt_u.dirty_queue = calloc(1, sizeof(*txn->mt_u.dirty_queue));
		if (txn->mt_u.dirty_queue == NULL) {
			free(txn);
			return ENOMEM;
		}
		SIMPLEQ_INIT(txn->mt_u.dirty_queue);

		pthread_mutex_lock(&env->me_txns->mt_wmutex);
		env->me_txns->mt_txnid++;
		txn->mt_free_pgs = malloc(MDB_IDL_UM_SIZEOF);
		if (txn->mt_free_pgs == NULL) {
			free(txn->mt_u.dirty_queue);
			free(txn);
			return ENOMEM;
		}
		txn->mt_free_pgs[0] = 0;
	}

	txn->mt_txnid = env->me_txns->mt_txnid;
	if (rdonly) {
		MDB_reader *r = pthread_getspecific(env->me_txkey);
		if (!r) {
			unsigned int i;
			pthread_mutex_lock(&env->me_txns->mt_mutex);
			for (i=0; i<env->me_maxreaders; i++) {
				if (env->me_txns->mt_readers[i].mr_pid == 0) {
					env->me_txns->mt_readers[i].mr_pid = getpid();
					env->me_txns->mt_readers[i].mr_tid = pthread_self();
					r = &env->me_txns->mt_readers[i];
					pthread_setspecific(env->me_txkey, r);
					if (i >= env->me_txns->mt_numreaders)
						env->me_txns->mt_numreaders = i+1;
					break;
				}
			}
			pthread_mutex_unlock(&env->me_txns->mt_mutex);
			if (i == env->me_maxreaders) {
				return ENOSPC;
			}
		}
		r->mr_txnid = txn->mt_txnid;
		txn->mt_u.reader = r;
	} else {
		env->me_txn = txn;
	}

	txn->mt_env = env;

	if ((rc = mdbenv_read_meta(env, &toggle)) != MDB_SUCCESS) {
		mdb_txn_abort(txn);
		return rc;
	}

	/* Copy the DB arrays */
	txn->mt_numdbs = env->me_numdbs;
	rc = (txn->mt_numdbs % DBX_CHUNK) + 1;
	txn->mt_dbxs = malloc(rc * DBX_CHUNK * sizeof(MDB_dbx));
	txn->mt_dbs = malloc(rc * DBX_CHUNK * sizeof(MDB_db *));
	memcpy(txn->mt_dbxs, env->me_dbxs, txn->mt_numdbs * sizeof(MDB_dbx));
	memcpy(txn->mt_dbs, env->me_dbs, txn->mt_numdbs * sizeof(MDB_db *));

	if (!rdonly) {
		memcpy(&txn->mt_db0, txn->mt_dbs[0], sizeof(txn->mt_db0));
		txn->mt_dbs[0] = &txn->mt_db0;
		if (toggle)
			txn->mt_flags |= MDB_TXN_METOGGLE;
		txn->mt_next_pgno = env->me_meta.mm_last_pg+1;
	}

	DPRINTF("begin transaction %lu on mdbenv %p, root page %lu",
		txn->mt_txnid, (void *) env, txn->mt_dbs[0]->md_root);

	*ret = txn;
	return MDB_SUCCESS;
}

void
mdb_txn_abort(MDB_txn *txn)
{
	MDB_dpage *dp;
	MDB_env	*env;

	if (txn == NULL)
		return;

	env = txn->mt_env;
	DPRINTF("abort transaction %lu on mdbenv %p, root page %lu",
		txn->mt_txnid, (void *) env, txn->mt_dbs[0]->md_root);

	free(txn->mt_dbs);
	free(txn->mt_dbxs);

	if (F_ISSET(txn->mt_flags, MDB_TXN_RDONLY)) {
		txn->mt_u.reader->mr_txnid = 0;
	} else {
		/* Discard all dirty pages. Return any re-used pages
		 * to the free list.
		 */
		MDB_IDL_ZERO(txn->mt_free_pgs);
		while (!SIMPLEQ_EMPTY(txn->mt_u.dirty_queue)) {
			dp = SIMPLEQ_FIRST(txn->mt_u.dirty_queue);
			SIMPLEQ_REMOVE_HEAD(txn->mt_u.dirty_queue, h.md_next);
			if (dp->p.mp_pgno <= env->me_meta.mm_last_pg)
				mdb_idl_insert(txn->mt_free_pgs, dp->p.mp_pgno);
			free(dp);
		}
		/* put back to head of free list */
		if (!MDB_IDL_IS_ZERO(txn->mt_free_pgs)) {
			MDB_oldpages *mop;

			mop = malloc(sizeof(MDB_oldpages) + MDB_IDL_SIZEOF(txn->mt_free_pgs) - sizeof(pgno_t));
			mop->mo_next = env->me_pghead;
			mop->mo_txnid = txn->mt_oldest - 1;
			if (!env->me_pghead) {
				env->me_pgtail = mop;
			}
			env->me_pghead = mop;
			memcpy(mop->mo_pages, txn->mt_free_pgs, MDB_IDL_SIZEOF(txn->mt_free_pgs));
		}

		free(txn->mt_free_pgs);
		free(txn->mt_u.dirty_queue);
		env->me_txn = NULL;
		env->me_txns->mt_txnid--;
		pthread_mutex_unlock(&env->me_txns->mt_wmutex);
	}

	free(txn);
}

int
mdb_txn_commit(MDB_txn *txn)
{
	int		 n, done;
	ssize_t		 rc;
	off_t		 size;
	MDB_dpage	*dp;
	MDB_env	*env;
	pgno_t	next;
	struct iovec	 iov[MDB_COMMIT_PAGES];

	assert(txn != NULL);
	assert(txn->mt_env != NULL);

	env = txn->mt_env;

	if (F_ISSET(txn->mt_flags, MDB_TXN_RDONLY)) {
		DPRINTF("attempt to commit read-only transaction");
		mdb_txn_abort(txn);
		return EPERM;
	}

	if (txn != env->me_txn) {
		DPRINTF("attempt to commit unknown transaction");
		mdb_txn_abort(txn);
		return EINVAL;
	}

	if (F_ISSET(txn->mt_flags, MDB_TXN_ERROR)) {
		DPRINTF("error flag is set, can't commit");
		mdb_txn_abort(txn);
		return EINVAL;
	}

	if (SIMPLEQ_EMPTY(txn->mt_u.dirty_queue))
		goto done;

	DPRINTF("committing transaction %lu on mdbenv %p, root page %lu",
	    txn->mt_txnid, (void *) env, txn->mt_dbs[0]->md_root);

	/* Commit up to MDB_COMMIT_PAGES dirty pages to disk until done.
	 */
	next = 0;
	do {
		n = 0;
		done = 1;
		size = 0;
		SIMPLEQ_FOREACH(dp, txn->mt_u.dirty_queue, h.md_next) {
			if (dp->p.mp_pgno != next) {
				if (n) {
					DPRINTF("committing %u dirty pages", n);
					rc = writev(env->me_fd, iov, n);
					if (rc != size) {
						n = errno;
						if (rc > 0)
							DPRINTF("short write, filesystem full?");
						else
							DPRINTF("writev: %s", strerror(errno));
						mdb_txn_abort(txn);
						return n;
					}
					n = 0;
					size = 0;
				}
				lseek(env->me_fd, dp->p.mp_pgno * env->me_meta.mm_psize, SEEK_SET);
				next = dp->p.mp_pgno;
			}
			DPRINTF("committing page %lu", dp->p.mp_pgno);
			iov[n].iov_len = env->me_meta.mm_psize * dp->h.md_num;
			iov[n].iov_base = &dp->p;
			size += iov[n].iov_len;
			next = dp->p.mp_pgno + dp->h.md_num;
			/* clear dirty flag */
			dp->p.mp_flags &= ~P_DIRTY;
			if (++n >= MDB_COMMIT_PAGES) {
				done = 0;
				break;
			}
		}

		if (n == 0)
			break;

		DPRINTF("committing %u dirty pages", n);
		rc = writev(env->me_fd, iov, n);
		if (rc != size) {
			n = errno;
			if (rc > 0)
				DPRINTF("short write, filesystem full?");
			else
				DPRINTF("writev: %s", strerror(errno));
			mdb_txn_abort(txn);
			return n;
		}

	} while (!done);

	/* Drop the dirty pages.
	 */
	while (!SIMPLEQ_EMPTY(txn->mt_u.dirty_queue)) {
		dp = SIMPLEQ_FIRST(txn->mt_u.dirty_queue);
		SIMPLEQ_REMOVE_HEAD(txn->mt_u.dirty_queue, h.md_next);
		free(dp);
	}

	if ((n = mdbenv_sync(env)) != 0 ||
	    (n = mdbenv_write_meta(txn)) != MDB_SUCCESS ||
	    (n = mdbenv_sync(env)) != 0) {
		mdb_txn_abort(txn);
		return n;
	}
	env->me_txn = NULL;

	{
		MDB_dbx *p1 = env->me_dbxs;
		MDB_db **p2 = env->me_dbs;

		txn->mt_dbs[0] = env->me_dbs[0];
		env->me_dbxs = txn->mt_dbxs;
		env->me_dbs = txn->mt_dbs;
		env->me_numdbs = txn->mt_numdbs;

		free(p2);
		free(p1);
	}

	/* add to tail of free list */
	if (!MDB_IDL_IS_ZERO(txn->mt_free_pgs)) {
		MDB_oldpages *mop;

		mop = malloc(sizeof(MDB_oldpages) + MDB_IDL_SIZEOF(txn->mt_free_pgs) - sizeof(pgno_t));
		mop->mo_next = NULL;
		if (env->me_pghead) {
			env->me_pgtail->mo_next = mop;
		} else {
			env->me_pghead = mop;
		}
		env->me_pgtail = mop;
		memcpy(mop->mo_pages, txn->mt_free_pgs, MDB_IDL_SIZEOF(txn->mt_free_pgs));
		mop->mo_txnid = txn->mt_txnid;
	}

	pthread_mutex_unlock(&env->me_txns->mt_wmutex);
	free(txn->mt_free_pgs);
	free(txn->mt_u.dirty_queue);
	free(txn);
	txn = NULL;

done:
	mdb_txn_abort(txn);

	return MDB_SUCCESS;
}

static int
mdbenv_read_header(MDB_env *env)
{
	char		 page[PAGESIZE];
	MDB_page	*p;
	MDB_meta	*m;
	int		 rc;

	assert(env != NULL);

	/* We don't know the page size yet, so use a minimum value.
	 */

	if ((rc = pread(env->me_fd, page, PAGESIZE, 0)) == 0) {
		return ENOENT;
	} else if (rc != PAGESIZE) {
		if (rc > 0)
			errno = EINVAL;
		DPRINTF("read: %s", strerror(errno));
		return errno;
	}

	p = (MDB_page *)page;

	if (!F_ISSET(p->mp_flags, P_META)) {
		DPRINTF("page %lu not a meta page", p->mp_pgno);
		return EINVAL;
	}

	m = METADATA(p);
	if (m->mm_magic != MDB_MAGIC) {
		DPRINTF("meta has invalid magic");
		return EINVAL;
	}

	if (m->mm_version != MDB_VERSION) {
		DPRINTF("database is version %u, expected version %u",
		    m->mm_version, MDB_VERSION);
		return EINVAL;
	}

	memcpy(&env->me_meta, m, sizeof(*m));
	return 0;
}

static int
mdbenv_init_meta(MDB_env *env)
{
	MDB_page *p, *q;
	MDB_meta *meta;
	int rc;
	unsigned int	 psize;

	DPRINTF("writing new meta page");
	psize = sysconf(_SC_PAGE_SIZE);

	env->me_meta.mm_magic = MDB_MAGIC;
	env->me_meta.mm_version = MDB_VERSION;
	env->me_meta.mm_psize = psize;
	env->me_meta.mm_flags = env->me_flags & 0xffff;
	env->me_meta.mm_root = P_INVALID;
	env->me_meta.mm_last_pg = 1;

	p = calloc(2, psize);
	p->mp_pgno = 0;
	p->mp_flags = P_META;

	meta = METADATA(p);
	memcpy(meta, &env->me_meta, sizeof(*meta));

	q = (MDB_page *)((char *)p + psize);

	q->mp_pgno = 1;
	q->mp_flags = P_META;

	meta = METADATA(q);
	memcpy(meta, &env->me_meta, sizeof(*meta));

	rc = write(env->me_fd, p, psize * 2);
	free(p);
	return (rc == (int)psize * 2) ? MDB_SUCCESS : errno;
}

static int
mdbenv_write_meta(MDB_txn *txn)
{
	MDB_env *env;
	MDB_meta	meta;
	off_t off;
	int rc, len;
	char *ptr;

	assert(txn != NULL);
	assert(txn->mt_env != NULL);

	DPRINTF("writing meta page for root page %lu", txn->mt_dbs[0]->md_root);

	env = txn->mt_env;

	ptr = (char *)&meta;
	off = offsetof(MDB_meta, mm_last_pg);
	len = sizeof(MDB_meta) - off;

	ptr += off;
	meta.mm_last_pg = txn->mt_next_pgno - 1;
	meta.mm_txnid = txn->mt_txnid;
	meta.mm_psize = env->me_meta.mm_psize;
	meta.mm_flags = env->me_meta.mm_flags;
	meta.mm_depth = txn->mt_dbs[0]->md_depth;
	meta.mm_branch_pages = txn->mt_dbs[0]->md_branch_pages;
	meta.mm_leaf_pages = txn->mt_dbs[0]->md_leaf_pages;
	meta.mm_overflow_pages = txn->mt_dbs[0]->md_overflow_pages;
	meta.mm_entries = txn->mt_dbs[0]->md_entries;
	meta.mm_root = txn->mt_dbs[0]->md_root;

	if (!F_ISSET(txn->mt_flags, MDB_TXN_METOGGLE))
		off += env->me_meta.mm_psize;
	off += PAGEHDRSZ;

	lseek(env->me_fd, off, SEEK_SET);
	rc = write(env->me_fd, ptr, len);
	if (rc != len) {
		DPRINTF("write failed, disk error?");
		return errno;
	}

	return MDB_SUCCESS;
}

/* Returns true if page p is a valid meta page, false otherwise.
 */
static int
mdb_check_meta_page(MDB_page *p)
{
	if (!F_ISSET(p->mp_flags, P_META)) {
		DPRINTF("page %lu not a meta page", p->mp_pgno);
		return EINVAL;
	}

	return 0;
}

static int
mdbenv_read_meta(MDB_env *env, int *which)
{
	MDB_page	*mp0, *mp1;
	MDB_meta	*meta[2];
	int toggle = 0, rc;

	assert(env != NULL);

	if ((mp0 = mdbenv_get_page(env, 0)) == NULL ||
		(mp1 = mdbenv_get_page(env, 1)) == NULL)
		return EIO;

	rc = mdb_check_meta_page(mp0);
	if (rc) return rc;

	rc = mdb_check_meta_page(mp1);
	if (rc) return rc;

	meta[0] = METADATA(mp0);
	meta[1] = METADATA(mp1);

	if (meta[0]->mm_txnid < meta[1]->mm_txnid)
		toggle = 1;

	if (meta[toggle]->mm_txnid > env->me_meta.mm_txnid) {
		memcpy(&env->me_meta, meta[toggle], sizeof(env->me_meta));
		if (which)
			*which = toggle;
	}

	DPRINTF("Using meta page %d", toggle);

	return MDB_SUCCESS;
}

int
mdbenv_create(MDB_env **env)
{
	MDB_env *e;

	e = calloc(1, sizeof(*e));
	if (!e) return ENOMEM;

	e->me_meta.mm_mapsize = DEFAULT_MAPSIZE;
	e->me_maxreaders = DEFAULT_READERS;
	e->me_fd = -1;
	e->me_lfd = -1;
	*env = e;
	return MDB_SUCCESS;
}

int
mdbenv_set_mapsize(MDB_env *env, size_t size)
{
	if (env->me_map)
		return EINVAL;
	env->me_mapsize = env->me_meta.mm_mapsize = size;
	return MDB_SUCCESS;
}

int
mdbenv_set_maxreaders(MDB_env *env, int readers)
{
	env->me_maxreaders = readers;
	return MDB_SUCCESS;
}

int
mdbenv_get_maxreaders(MDB_env *env, int *readers)
{
	if (!env || !readers)
		return EINVAL;
	*readers = env->me_maxreaders;
	return MDB_SUCCESS;
}

int
mdbenv_open2(MDB_env *env, unsigned int flags)
{
	int i, newenv = 0;

	env->me_flags = flags;

	if ((i = mdbenv_read_header(env)) != 0) {
		if (i != ENOENT)
			return i;
		DPRINTF("new mdbenv");
		newenv = 1;
	}

	if (!env->me_mapsize)
		env->me_mapsize = env->me_meta.mm_mapsize;

	i = MAP_SHARED;
	if (env->me_meta.mm_address && (flags & MDB_FIXEDMAP))
		i |= MAP_FIXED;
	env->me_map = mmap(env->me_meta.mm_address, env->me_mapsize, PROT_READ, i,
		env->me_fd, 0);
	if (env->me_map == MAP_FAILED)
		return errno;

	if (newenv) {
		env->me_meta.mm_mapsize = env->me_mapsize;
		if (flags & MDB_FIXEDMAP)
			env->me_meta.mm_address = env->me_map;
		i = mdbenv_init_meta(env);
		if (i != MDB_SUCCESS) {
			munmap(env->me_map, env->me_mapsize);
			return i;
		}
	}

	if ((i = mdbenv_read_meta(env, NULL)) != 0)
		return i;

	DPRINTF("opened database version %u, pagesize %u",
	    env->me_meta.mm_version, env->me_meta.mm_psize);
	DPRINTF("depth: %u", env->me_meta.mm_depth);
	DPRINTF("entries: %lu", env->me_meta.mm_entries);
	DPRINTF("branch pages: %lu", env->me_meta.mm_branch_pages);
	DPRINTF("leaf pages: %lu", env->me_meta.mm_leaf_pages);
	DPRINTF("overflow pages: %lu", env->me_meta.mm_overflow_pages);
	DPRINTF("root: %lu", env->me_meta.mm_root);

	return MDB_SUCCESS;
}

static void
mdbenv_reader_dest(void *ptr)
{
	MDB_reader *reader = ptr;

	reader->mr_txnid = 0;
	reader->mr_pid = 0;
	reader->mr_tid = 0;
}

static void
mdbenv_share_locks(MDB_env *env)
{
	struct flock lock_info;

	env->me_txns->mt_txnid = env->me_meta.mm_txnid;

	memset((void *)&lock_info, 0, sizeof(lock_info));
	lock_info.l_type = F_RDLCK;
	lock_info.l_whence = SEEK_SET;
	lock_info.l_start = 0;
	lock_info.l_len = 1;
	fcntl(env->me_lfd, F_SETLK, &lock_info);
}

static int
mdbenv_setup_locks(MDB_env *env, char *lpath, int mode, int *excl)
{
	int rc;
	off_t size, rsize;
	struct flock lock_info;

	*excl = 0;

	if ((env->me_lfd = open(lpath, O_RDWR|O_CREAT, mode)) == -1) {
		rc = errno;
		return rc;
	}
	/* Try to get exclusive lock. If we succeed, then
	 * nobody is using the lock region and we should initialize it.
	 */
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
		rc = fcntl(env->me_lfd, F_SETLK, &lock_info);
		if (rc) {
			rc = errno;
			goto fail;
		}
	}
	size = lseek(env->me_lfd, 0, SEEK_END);
	rsize = (env->me_maxreaders-1) * sizeof(MDB_reader) + sizeof(MDB_txninfo);
	if (size < rsize && *excl) {
		if (ftruncate(env->me_lfd, rsize) != 0) {
			rc = errno;
			goto fail;
		}
	} else {
		rsize = size;
		size = rsize - sizeof(MDB_txninfo);
		env->me_maxreaders = size/sizeof(MDB_reader) + 1;
	}
	env->me_txns = mmap(0, rsize, PROT_READ|PROT_WRITE, MAP_SHARED,
		env->me_lfd, 0);
	if (env->me_txns == MAP_FAILED) {
		rc = errno;
		goto fail;
	}
	if (*excl) {
		pthread_mutexattr_t mattr;

		pthread_mutexattr_init(&mattr);
		pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
		pthread_mutex_init(&env->me_txns->mt_mutex, &mattr);
		pthread_mutex_init(&env->me_txns->mt_wmutex, &mattr);
		env->me_txns->mt_version = MDB_VERSION;
		env->me_txns->mt_magic = MDB_MAGIC;
		env->me_txns->mt_txnid = 0;
		env->me_txns->mt_numreaders = 0;

	} else {
		if (env->me_txns->mt_magic != MDB_MAGIC) {
			DPRINTF("lock region has invalid magic");
			errno = EINVAL;
		}
		if (env->me_txns->mt_version != MDB_VERSION) {
			DPRINTF("lock region is version %u, expected version %u",
				env->me_txns->mt_version, MDB_VERSION);
			errno = EINVAL;
		}
		if (errno != EACCES && errno != EAGAIN) {
			rc = errno;
			goto fail;
		}
	}
	return MDB_SUCCESS;

fail:
	close(env->me_lfd);
	return rc;

}

int
mdbenv_open(MDB_env *env, const char *path, unsigned int flags, mode_t mode)
{
	int		oflags, rc, len, excl;
	char *lpath, *dpath;

	len = strlen(path);
	lpath = malloc(len + sizeof("/lock.mdb") + len + sizeof("/data.db"));
	if (!lpath)
		return ENOMEM;
	dpath = lpath + len + sizeof("/lock.mdb");
	sprintf(lpath, "%s/lock.mdb", path);
	sprintf(dpath, "%s/data.mdb", path);

	rc = mdbenv_setup_locks(env, lpath, mode, &excl);
	if (rc)
		goto leave;

	if (F_ISSET(flags, MDB_RDONLY))
		oflags = O_RDONLY;
	else
		oflags = O_RDWR | O_CREAT;

	if ((env->me_fd = open(dpath, oflags, mode)) == -1)
		return errno;

	if ((rc = mdbenv_open2(env, flags)) != MDB_SUCCESS) {
		close(env->me_fd);
		env->me_fd = -1;
	} else {
		env->me_path = strdup(path);
		DPRINTF("opened dbenv %p", (void *) env);
		pthread_key_create(&env->me_txkey, mdbenv_reader_dest);
		if (excl)
			mdbenv_share_locks(env);
		env->me_dbxs = calloc(DBX_CHUNK, sizeof(MDB_dbx));
		env->me_dbs = calloc(DBX_CHUNK, sizeof(MDB_db *));
		env->me_numdbs = 1;
		env->me_dbs[0] = (MDB_db *)&env->me_meta.mm_psize;
	}


leave:
	free(lpath);
	return rc;
}

void
mdbenv_close(MDB_env *env)
{
	if (env == NULL)
		return;

	free(env->me_dbs);
	free(env->me_dbxs);
	free(env->me_path);

	if (env->me_map) {
		munmap(env->me_map, env->me_mapsize);
	}
	close(env->me_fd);
	if (env->me_txns) {
		size_t size = (env->me_maxreaders-1) * sizeof(MDB_reader) + sizeof(MDB_txninfo);
		munmap(env->me_txns, size);
	}
	close(env->me_lfd);
	free(env);
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
	unsigned int	 i = 0;
	int		 low, high;
	int		 rc = 0;
	MDB_node	*node;
	MDB_val	 nodekey;

	DPRINTF("searching %u keys in %s page %lu",
	    NUMKEYS(mp),
	    IS_LEAF(mp) ? "leaf" : "branch",
	    mp->mp_pgno);

	assert(NUMKEYS(mp) > 0);

	memset(&nodekey, 0, sizeof(nodekey));

	low = IS_LEAF(mp) ? 0 : 1;
	high = NUMKEYS(mp) - 1;
	while (low <= high) {
		i = (low + high) >> 1;
		node = NODEPTR(mp, i);

		nodekey.mv_size = node->mn_ksize;
		nodekey.mv_data = NODEKEY(node);

		if (txn->mt_dbxs[dbi].md_cmp)
			rc = txn->mt_dbxs[dbi].md_cmp(key, &nodekey);
		else
			rc = _mdb_cmp(txn, dbi, key, &nodekey);

		if (IS_LEAF(mp))
			DPRINTF("found leaf index %u [%.*s], rc = %i",
			    i, (int)nodekey.mv_size, (char *)nodekey.mv_data, rc);
		else
			DPRINTF("found branch index %u [%.*s -> %lu], rc = %i",
			    i, (int)node->mn_ksize, (char *)NODEKEY(node),
			    node->mn_pgno, rc);

		if (rc == 0)
			break;
		if (rc > 0)
			low = i + 1;
		else
			high = i - 1;
	}

	if (rc > 0) {	/* Found entry is less than the key. */
		i++;	/* Skip to get the smallest entry larger than key. */
		if (i >= NUMKEYS(mp))
			/* There is no entry larger or equal to the key. */
			return NULL;
	}
	if (exactp)
		*exactp = (rc == 0);
	if (kip)	/* Store the key index if requested. */
		*kip = i;

	return NODEPTR(mp, i);
}

static void
cursor_pop_page(MDB_cursor *cursor)
{
	MDB_ppage	*top;

	top = CURSOR_TOP(cursor);
	CURSOR_POP(cursor);

	DPRINTF("popped page %lu off cursor %p", top->mp_page->mp_pgno, (void *) cursor);

	free(top);
}

static MDB_ppage *
cursor_push_page(MDB_cursor *cursor, MDB_page *mp)
{
	MDB_ppage	*ppage;

	DPRINTF("pushing page %lu on cursor %p", mp->mp_pgno, (void *) cursor);

	if ((ppage = calloc(1, sizeof(*ppage))) == NULL)
		return NULL;
	ppage->mp_page = mp;
	CURSOR_PUSH(cursor, ppage);
	return ppage;
}

static MDB_page *
mdbenv_get_page(MDB_env *env, pgno_t pgno)
{
	MDB_page *p = NULL;
	MDB_txn *txn = env->me_txn;
	int found = 0;

	if (txn && !SIMPLEQ_EMPTY(txn->mt_u.dirty_queue)) {
		MDB_dpage *dp;
		SIMPLEQ_FOREACH(dp, txn->mt_u.dirty_queue, h.md_next) {
			if (dp->p.mp_pgno == pgno) {
				p = &dp->p;
				found = 1;
				break;
			}
		}
	}
	if (!found) {
		p = (MDB_page *)(env->me_map + env->me_meta.mm_psize * pgno);
	}
	return p;
}

static int
mdb_search_page_root(MDB_txn *txn, MDB_dbi dbi, MDB_val *key,
    MDB_cursor *cursor, int modify, MDB_pageparent *mpp)
{
	MDB_page	*mp = mpp->mp_page;
	int rc;

	if (cursor && cursor_push_page(cursor, mp) == NULL)
		return MDB_FAIL;

	while (IS_BRANCH(mp)) {
		unsigned int	 i = 0;
		MDB_node	*node;

		DPRINTF("branch page %lu has %u keys", mp->mp_pgno, NUMKEYS(mp));
		assert(NUMKEYS(mp) > 1);
		DPRINTF("found index 0 to page %lu", NODEPGNO(NODEPTR(mp, 0)));

		if (key == NULL)	/* Initialize cursor to first page. */
			i = 0;
		else {
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
			DPRINTF("following index %u for key %.*s",
			    i, (int)key->mv_size, (char *)key->mv_data);
		assert(i < NUMKEYS(mp));
		node = NODEPTR(mp, i);

		if (cursor)
			CURSOR_TOP(cursor)->mp_ki = i;

		mpp->mp_parent = mp;
		if ((mp = mdbenv_get_page(txn->mt_env, NODEPGNO(node))) == NULL)
			return MDB_FAIL;
		mpp->mp_pi = i;
		mpp->mp_page = mp;

		if (cursor && cursor_push_page(cursor, mp) == NULL)
			return MDB_FAIL;

		if (modify) {
			MDB_dhead *dh = ((MDB_dhead *)mp)-1;
			if ((rc = mdb_touch(txn, mpp)) != 0)
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
		return MDB_FAIL;
	}

	DPRINTF("found leaf page %lu for key %.*s", mp->mp_pgno,
	    key ? (int)key->mv_size : 0, key ? (char *)key->mv_data : NULL);

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
		DPRINTF("transaction has failed, must abort");
		return EINVAL;
	} else
		root = txn->mt_dbs[dbi]->md_root;

	if (root == P_INVALID) {		/* Tree is empty. */
		DPRINTF("tree is empty");
		return ENOENT;
	}

	if ((mpp->mp_page = mdbenv_get_page(txn->mt_env, root)) == NULL)
		return MDB_FAIL;

	DPRINTF("root page has flags 0x%X", mpp->mp_page->mp_flags);

	if (modify && !F_ISSET(mpp->mp_page->mp_flags, P_DIRTY)) {
		mpp->mp_parent = NULL;
		mpp->mp_pi = 0;
		if ((rc = mdb_touch(txn, mpp)))
			return rc;
		txn->mt_dbs[dbi]->md_root = mpp->mp_page->mp_pgno;
	}

	return mdb_search_page_root(txn, dbi, key, cursor, modify, mpp);
}

static int
mdb_read_data(MDB_env *env, MDB_node *leaf, MDB_val *data)
{
	MDB_page	*omp;		/* overflow mpage */
	pgno_t		 pgno;

	if (!F_ISSET(leaf->mn_flags, F_BIGDATA)) {
		data->mv_size = leaf->mn_dsize;
		data->mv_data = NODEDATA(leaf);
		return MDB_SUCCESS;
	}

	/* Read overflow data.
	 */
	data->mv_size = leaf->mn_dsize;
	memcpy(&pgno, NODEDATA(leaf), sizeof(pgno));
	if ((omp = mdbenv_get_page(env, pgno)) == NULL) {
		DPRINTF("read overflow page %lu failed", pgno);
		return MDB_FAIL;
	}
	data->mv_data = omp;

	return MDB_SUCCESS;
}

int
mdb_get(MDB_txn *txn, MDB_dbi dbi,
    MDB_val *key, MDB_val *data)
{
	int		 rc, exact;
	MDB_node	*leaf;
	MDB_pageparent mpp;

	assert(key);
	assert(data);
	DPRINTF("===> get key [%.*s]", (int)key->mv_size, (char *)key->mv_data);

	if (key->mv_size == 0 || key->mv_size > MAXKEYSIZE) {
		return EINVAL;
	}

	if ((rc = mdb_search_page(txn, dbi, key, NULL, 0, &mpp)) != MDB_SUCCESS)
		return rc;

	leaf = mdb_search_node(txn, dbi, mpp.mp_page, key, &exact, NULL);
	if (leaf && exact)
		rc = mdb_read_data(txn->mt_env, leaf, data);
	else {
		rc = ENOENT;
	}

	return rc;
}

static int
mdb_sibling(MDB_cursor *cursor, int move_right)
{
	int		 rc;
	MDB_node	*indx;
	MDB_ppage	*parent, *top;
	MDB_page	*mp;

	top = CURSOR_TOP(cursor);
	if ((parent = SLIST_NEXT(top, mp_entry)) == NULL) {
		return ENOENT;		/* root has no siblings */
	}

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
	if ((mp = mdbenv_get_page(cursor->mc_txn->mt_env, indx->mn_pgno)) == NULL)
		return MDB_FAIL;
#if 0
	mp->parent = parent->mp_page;
	mp->parent_index = parent->mp_ki;
#endif

	cursor_push_page(cursor, mp);

	return MDB_SUCCESS;
}

static int
mdb_set_key(MDB_node *node, MDB_val *key)
{
	if (key == NULL)
		return 0;

	key->mv_size = node->mn_ksize;
	key->mv_data = NODEKEY(node);

	return 0;
}

static int
mdb_cursor_next(MDB_cursor *cursor, MDB_val *key, MDB_val *data)
{
	MDB_ppage	*top;
	MDB_page	*mp;
	MDB_node	*leaf;

	if (cursor->mc_eof) {
		return ENOENT;
	}

	assert(cursor->mc_initialized);

	top = CURSOR_TOP(cursor);
	mp = top->mp_page;

	DPRINTF("cursor_next: top page is %lu in cursor %p", mp->mp_pgno, (void *) cursor);

	if (top->mp_ki + 1 >= NUMKEYS(mp)) {
		DPRINTF("=====> move to next sibling page");
		if (mdb_sibling(cursor, 1) != MDB_SUCCESS) {
			cursor->mc_eof = 1;
			return ENOENT;
		}
		top = CURSOR_TOP(cursor);
		mp = top->mp_page;
		DPRINTF("next page is %lu, key index %u", mp->mp_pgno, top->mp_ki);
	} else
		top->mp_ki++;

	DPRINTF("==> cursor points to page %lu with %u keys, key index %u",
	    mp->mp_pgno, NUMKEYS(mp), top->mp_ki);

	assert(IS_LEAF(mp));
	leaf = NODEPTR(mp, top->mp_ki);

	if (data && mdb_read_data(cursor->mc_txn->mt_env, leaf, data) != MDB_SUCCESS)
		return MDB_FAIL;

	return mdb_set_key(leaf, key);
}

static int
mdb_cursor_set(MDB_cursor *cursor, MDB_val *key, MDB_val *data,
    int *exactp)
{
	int		 rc;
	MDB_node	*leaf;
	MDB_ppage	*top;
	MDB_pageparent mpp;

	assert(cursor);
	assert(key);
	assert(key->mv_size > 0);

	rc = mdb_search_page(cursor->mc_txn, cursor->mc_dbi, key, cursor, 0, &mpp);
	if (rc != MDB_SUCCESS)
		return rc;
	assert(IS_LEAF(mpp.mp_page));

	top = CURSOR_TOP(cursor);
	leaf = mdb_search_node(cursor->mc_txn, cursor->mc_dbi, mpp.mp_page, key, exactp, &top->mp_ki);
	if (exactp != NULL && !*exactp) {
		/* MDB_CURSOR_EXACT specified and not an exact match. */
		return ENOENT;
	}

	if (leaf == NULL) {
		DPRINTF("===> inexact leaf not found, goto sibling");
		if ((rc = mdb_sibling(cursor, 1)) != MDB_SUCCESS)
			return rc;		/* no entries matched */
		top = CURSOR_TOP(cursor);
		top->mp_ki = 0;
		mpp.mp_page = top->mp_page;
		assert(IS_LEAF(mpp.mp_page));
		leaf = NODEPTR(mpp.mp_page, 0);
	}

	cursor->mc_initialized = 1;
	cursor->mc_eof = 0;

	if (data && (rc = mdb_read_data(cursor->mc_txn->mt_env, leaf, data)) != MDB_SUCCESS)
		return rc;

	rc = mdb_set_key(leaf, key);
	if (rc == MDB_SUCCESS) {
		DPRINTF("==> cursor placed on key %.*s",
			(int)key->mv_size, (char *)key->mv_data);
		;
	}

	return rc;
}

static int
mdb_cursor_first(MDB_cursor *cursor, MDB_val *key, MDB_val *data)
{
	int		 rc;
	MDB_pageparent	mpp;
	MDB_node	*leaf;

	rc = mdb_search_page(cursor->mc_txn, cursor->mc_dbi, NULL, cursor, 0, &mpp);
	if (rc != MDB_SUCCESS)
		return rc;
	assert(IS_LEAF(mpp.mp_page));

	leaf = NODEPTR(mpp.mp_page, 0);
	cursor->mc_initialized = 1;
	cursor->mc_eof = 0;

	if (data && (rc = mdb_read_data(cursor->mc_txn->mt_env, leaf, data)) != MDB_SUCCESS)
		return rc;

	return mdb_set_key(leaf, key);
}

int
mdb_cursor_get(MDB_cursor *cursor, MDB_val *key, MDB_val *data,
    MDB_cursor_op op)
{
	int		 rc;
	int		 exact = 0;

	assert(cursor);

	switch (op) {
	case MDB_CURSOR:
	case MDB_CURSOR_EXACT:
		while (CURSOR_TOP(cursor) != NULL)
			cursor_pop_page(cursor);
		if (key == NULL || key->mv_size == 0 || key->mv_size > MAXKEYSIZE) {
			rc = EINVAL;
		} else if (op == MDB_CURSOR_EXACT)
			rc = mdb_cursor_set(cursor, key, data, &exact);
		else
			rc = mdb_cursor_set(cursor, key, data, NULL);
		break;
	case MDB_NEXT:
		if (!cursor->mc_initialized)
			rc = mdb_cursor_first(cursor, key, data);
		else
			rc = mdb_cursor_next(cursor, key, data);
		break;
	case MDB_FIRST:
		while (CURSOR_TOP(cursor) != NULL)
			cursor_pop_page(cursor);
		rc = mdb_cursor_first(cursor, key, data);
		break;
	default:
		DPRINTF("unhandled/unimplemented cursor operation %u", op);
		rc = EINVAL;
		break;
	}

	return rc;
}

/* Allocate a page and initialize it
 */
static MDB_dpage *
mdb_new_page(MDB_txn *txn, MDB_dbi dbi, uint32_t flags, int num)
{
	MDB_dpage	*dp;

	if ((dp = mdb_alloc_page(txn, NULL, 0, num)) == NULL)
		return NULL;
	DPRINTF("allocated new mpage %lu, page size %u",
	    dp->p.mp_pgno, txn->mt_env->me_meta.mm_psize);
	dp->p.mp_flags = flags | P_DIRTY;
	dp->p.mp_lower = PAGEHDRSZ;
	dp->p.mp_upper = txn->mt_env->me_meta.mm_psize;

	if (IS_BRANCH(&dp->p))
		txn->mt_dbs[dbi]->md_branch_pages++;
	else if (IS_LEAF(&dp->p))
		txn->mt_dbs[dbi]->md_leaf_pages++;
	else if (IS_OVERFLOW(&dp->p)) {
		txn->mt_dbs[dbi]->md_overflow_pages += num;
		dp->p.mp_pages = num;
	}

	return dp;
}

static size_t
mdb_leaf_size(MDB_env *env, MDB_val *key, MDB_val *data)
{
	size_t		 sz;

	sz = LEAFSIZE(key, data);
	if (data->mv_size >= env->me_meta.mm_psize / MDB_MINKEYS) {
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
	if (sz >= env->me_meta.mm_psize / MDB_MINKEYS) {
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

	assert(mp->mp_upper >= mp->mp_lower);

	DPRINTF("add node [%.*s] to %s page %lu at index %i, key size %zu",
	    key ? (int)key->mv_size : 0, key ? (char *)key->mv_data : NULL,
	    IS_LEAF(mp) ? "leaf" : "branch",
	    mp->mp_pgno, indx, key ? key->mv_size : 0);

	if (key != NULL)
		node_size += key->mv_size;

	if (IS_LEAF(mp)) {
		assert(data);
		if (F_ISSET(flags, F_BIGDATA)) {
			/* Data already on overflow page. */
			node_size += sizeof(pgno_t);
		} else if (data->mv_size >= txn->mt_env->me_meta.mm_psize / MDB_MINKEYS) {
			int ovpages = OVPAGES(data->mv_size, txn->mt_env->me_meta.mm_psize);
			/* Put data on overflow page. */
			DPRINTF("data size is %zu, put on overflow page",
			    data->mv_size);
			node_size += sizeof(pgno_t);
			if ((ofp = mdb_new_page(txn, dbi, P_OVERFLOW, ovpages)) == NULL)
				return MDB_FAIL;
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
		node->mn_pgno = pgno;

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
mdb_del_node(MDB_page *mp, indx_t indx)
{
	unsigned int	 sz;
	indx_t		 i, j, numkeys, ptr;
	MDB_node	*node;
	char		*base;

	DPRINTF("delete node %u on %s page %lu", indx,
	    IS_LEAF(mp) ? "leaf" : "branch", mp->mp_pgno);
	assert(indx < NUMKEYS(mp));

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

int
mdb_cursor_open(MDB_txn *txn, MDB_dbi dbi, MDB_cursor **ret)
{
	MDB_cursor	*cursor;

	if (txn == NULL || ret == NULL)
		return EINVAL;

	if ((cursor = calloc(1, sizeof(*cursor))) != NULL) {
		SLIST_INIT(&cursor->mc_stack);
		cursor->mc_dbi = dbi;
		cursor->mc_txn = txn;
	}

	*ret = cursor;

	return MDB_SUCCESS;
}

void
mdb_cursor_close(MDB_cursor *cursor)
{
	if (cursor != NULL) {
		while (!CURSOR_EMPTY(cursor))
			cursor_pop_page(cursor);

/*		btree_close(cursor->bt); */
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

	node = NODEPTR(mp, indx);
	ptr = mp->mp_ptrs[indx];
	DPRINTF("update key %u (ofs %u) [%.*s] to [%.*s] on page %lu",
	    indx, ptr,
	    (int)node->mn_ksize, (char *)NODEKEY(node),
	    (int)key->mv_size, (char *)key->mv_data,
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

	srcnode = NODEPTR(src->mp_page, srcindx);
	DPRINTF("moving %s node %u [%.*s] on page %lu to node %u on page %lu",
	    IS_LEAF(src->mp_page) ? "leaf" : "branch",
	    srcindx,
	    (int)srcnode->mn_ksize, (char *)NODEKEY(srcnode),
	    src->mp_page->mp_pgno,
	    dstindx, dst->mp_page->mp_pgno);

	/* Mark src and dst as dirty. */
	if ((rc = mdb_touch(txn, src)) ||
	    (rc = mdb_touch(txn, dst)))
		return rc;;

	/* Add the node to the destination page.
	 */
	key.mv_size = srcnode->mn_ksize;
	key.mv_data = NODEKEY(srcnode);
	data.mv_size = NODEDSZ(srcnode);
	data.mv_data = NODEDATA(srcnode);
	rc = mdb_add_node(txn, dbi, dst->mp_page, dstindx, &key, &data, NODEPGNO(srcnode),
	    srcnode->mn_flags);
	if (rc != MDB_SUCCESS)
		return rc;

	/* Delete the node from the source page.
	 */
	mdb_del_node(src->mp_page, srcindx);

	/* Update the parent separators.
	 */
	if (srcindx == 0 && src->mp_pi != 0) {
		DPRINTF("update separator for source page %lu to [%.*s]",
		    src->mp_page->mp_pgno, (int)key.mv_size, (char *)key.mv_data);
		if ((rc = mdb_update_key(src->mp_parent, src->mp_pi,
		    &key)) != MDB_SUCCESS)
			return rc;
	}

	if (srcindx == 0 && IS_BRANCH(src->mp_page)) {
		MDB_val	 nullkey;
		nullkey.mv_size = 0;
		assert(mdb_update_key(src->mp_page, 0, &nullkey) == MDB_SUCCESS);
	}

	if (dstindx == 0 && dst->mp_pi != 0) {
		DPRINTF("update separator for destination page %lu to [%.*s]",
		    dst->mp_page->mp_pgno, (int)key.mv_size, (char *)key.mv_data);
		if ((rc = mdb_update_key(dst->mp_parent, dst->mp_pi,
		    &key)) != MDB_SUCCESS)
			return rc;
	}

	if (dstindx == 0 && IS_BRANCH(dst->mp_page)) {
		MDB_val	 nullkey;
		nullkey.mv_size = 0;
		assert(mdb_update_key(dst->mp_page, 0, &nullkey) == MDB_SUCCESS);
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
	if ((rc = mdb_touch(txn, src)) ||
	    (rc = mdb_touch(txn, dst)))
		return rc;

	/* Move all nodes from src to dst.
	 */
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

	DPRINTF("dst page %lu now has %u keys (%.1f%% filled)",
	    dst->mp_page->mp_pgno, NUMKEYS(dst->mp_page), (float)PAGEFILL(txn->mt_env, dst->mp_page) / 10);

	/* Unlink the src page from parent.
	 */
	mdb_del_node(src->mp_parent, src->mp_pi);
	if (src->mp_pi == 0) {
		key.mv_size = 0;
		if ((rc = mdb_update_key(src->mp_parent, 0, &key)) != MDB_SUCCESS)
			return rc;
	}

	if (IS_LEAF(src->mp_page))
		txn->mt_dbs[dbi]->md_leaf_pages--;
	else
		txn->mt_dbs[dbi]->md_branch_pages--;

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
			DPRINTF("tree is completely empty");
			txn->mt_dbs[dbi]->md_root = P_INVALID;
			txn->mt_dbs[dbi]->md_depth--;
			txn->mt_dbs[dbi]->md_leaf_pages--;
		} else if (IS_BRANCH(mpp->mp_page) && NUMKEYS(mpp->mp_page) == 1) {
			DPRINTF("collapsing root page!");
			txn->mt_dbs[dbi]->md_root = NODEPGNO(NODEPTR(mpp->mp_page, 0));
			if ((root = mdbenv_get_page(txn->mt_env, txn->mt_dbs[dbi]->md_root)) == NULL)
				return MDB_FAIL;
			txn->mt_dbs[dbi]->md_depth--;
			txn->mt_dbs[dbi]->md_branch_pages--;
		} else
			DPRINTF("root page doesn't need rebalancing");
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
		DPRINTF("reading right neighbor");
		node = NODEPTR(mpp->mp_parent, mpp->mp_pi + 1);
		if ((npp.mp_page = mdbenv_get_page(txn->mt_env, NODEPGNO(node))) == NULL)
			return MDB_FAIL;
		npp.mp_pi = mpp->mp_pi + 1;
		si = 0;
		di = NUMKEYS(mpp->mp_page);
	} else {
		/* There is at least one neighbor to the left.
		 */
		DPRINTF("reading left neighbor");
		node = NODEPTR(mpp->mp_parent, mpp->mp_pi - 1);
		if ((npp.mp_page = mdbenv_get_page(txn->mt_env, NODEPGNO(node))) == NULL)
			return MDB_FAIL;
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

int
mdb_del(MDB_txn *txn, MDB_dbi dbi,
    MDB_val *key, MDB_val *data)
{
	int		 rc, exact;
	unsigned int	 ki;
	MDB_node	*leaf;
	MDB_pageparent	mpp;

	DPRINTF("========> delete key %.*s", (int)key->mv_size, (char *)key->mv_data);

	assert(key != NULL);

	if (txn == NULL || dbi >= txn->mt_numdbs)
		return EINVAL;

	if (F_ISSET(txn->mt_flags, MDB_TXN_RDONLY)) {
		return EINVAL;
	}

	if (key->mv_size == 0 || key->mv_size > MAXKEYSIZE) {
		return EINVAL;
	}

	if ((rc = mdb_search_page(txn, dbi, key, NULL, 1, &mpp)) != MDB_SUCCESS)
		return rc;

	leaf = mdb_search_node(txn, dbi, mpp.mp_page, key, &exact, &ki);
	if (leaf == NULL || !exact) {
		return ENOENT;
	}

	if (data && (rc = mdb_read_data(txn->mt_env, leaf, data)) != MDB_SUCCESS)
		return rc;

	mdb_del_node(mpp.mp_page, ki);
	/* add overflow pages to free list */
	if (F_ISSET(leaf->mn_flags, F_BIGDATA)) {
		int i, ovpages;
		pgno_t pg;

		memcpy(&pg, NODEDATA(leaf), sizeof(pg));
		ovpages = OVPAGES(NODEDSZ(leaf), txn->mt_env->me_meta.mm_psize);
		for (i=0; i<ovpages; i++) {
			mdb_idl_insert(txn->mt_free_pgs, pg);
			pg++;
		}
	}
	txn->mt_dbs[dbi]->md_entries--;
	rc = mdb_rebalance(txn, dbi, &mpp);
	if (rc != MDB_SUCCESS)
		txn->mt_flags |= MDB_TXN_ERROR;

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
	unsigned int	 i, j, split_indx;
	MDB_node	*node;
	MDB_val	 sepkey, rkey, rdata;
	MDB_page	*copy;
	MDB_dpage	*mdp, *rdp, *pdp;
	MDB_dhead *dh;

	assert(txn != NULL);

	dh = ((MDB_dhead *)*mpp) - 1;
	mdp = (MDB_dpage *)dh;
	newindx = *newindxp;

	DPRINTF("-----> splitting %s page %lu and adding [%.*s] at index %i",
	    IS_LEAF(&mdp->p) ? "leaf" : "branch", mdp->p.mp_pgno,
	    (int)newkey->mv_size, (char *)newkey->mv_data, *newindxp);

	if (mdp->h.md_parent == NULL) {
		if ((pdp = mdb_new_page(txn, dbi, P_BRANCH, 1)) == NULL)
			return MDB_FAIL;
		mdp->h.md_pi = 0;
		mdp->h.md_parent = &pdp->p;
		txn->mt_dbs[dbi]->md_root = pdp->p.mp_pgno;
		DPRINTF("root split! new root = %lu", pdp->p.mp_pgno);
		txn->mt_dbs[dbi]->md_depth++;

		/* Add left (implicit) pointer. */
		if (mdb_add_node(txn, dbi, &pdp->p, 0, NULL, NULL,
		    mdp->p.mp_pgno, 0) != MDB_SUCCESS)
			return MDB_FAIL;
	} else {
		DPRINTF("parent branch page is %lu", mdp->h.md_parent->mp_pgno);
	}

	/* Create a right sibling. */
	if ((rdp = mdb_new_page(txn, dbi, mdp->p.mp_flags, 1)) == NULL)
		return MDB_FAIL;
	rdp->h.md_parent = mdp->h.md_parent;
	rdp->h.md_pi = mdp->h.md_pi + 1;
	DPRINTF("new right sibling: page %lu", rdp->p.mp_pgno);

	/* Move half of the keys to the right sibling. */
	if ((copy = malloc(txn->mt_env->me_meta.mm_psize)) == NULL)
		return MDB_FAIL;
	memcpy(copy, &mdp->p, txn->mt_env->me_meta.mm_psize);
	memset(&mdp->p.mp_ptrs, 0, txn->mt_env->me_meta.mm_psize - PAGEHDRSZ);
	mdp->p.mp_lower = PAGEHDRSZ;
	mdp->p.mp_upper = txn->mt_env->me_meta.mm_psize;

	split_indx = NUMKEYS(copy) / 2 + 1;

	/* First find the separating key between the split pages.
	 */
	memset(&sepkey, 0, sizeof(sepkey));
	if (newindx == split_indx) {
		sepkey.mv_size = newkey->mv_size;
		sepkey.mv_data = newkey->mv_data;
	} else {
		node = NODEPTR(copy, split_indx);
		sepkey.mv_size = node->mn_ksize;
		sepkey.mv_data = NODEKEY(node);
	}

	DPRINTF("separator is [%.*s]", (int)sepkey.mv_size, (char *)sepkey.mv_data);

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
	if (rc != MDB_SUCCESS) {
		free(copy);
		return MDB_FAIL;
	}

	for (i = j = 0; i <= NUMKEYS(copy); j++) {
		if (i < split_indx) {
			/* Re-insert in left sibling. */
			pdp = mdp;
		} else {
			/* Insert in right sibling. */
			if (i == split_indx)
				/* Reset insert index for right sibling. */
				j = (i == newindx && ins_new);
			pdp = rdp;
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
			*mpp = &pdp->p;
		} else if (i == NUMKEYS(copy)) {
			break;
		} else {
			node = NODEPTR(copy, i);
			rkey.mv_data = NODEKEY(node);
			rkey.mv_size = node->mn_ksize;
			if (IS_LEAF(&mdp->p)) {
				rdata.mv_data = NODEDATA(node);
				rdata.mv_size = node->mn_dsize;
			} else
				pgno = node->mn_pgno;
			flags = node->mn_flags;

			i++;
		}

		if (!IS_LEAF(&mdp->p) && j == 0) {
			/* First branch index doesn't need key data. */
			rkey.mv_size = 0;
		}

		rc = mdb_add_node(txn, dbi, &pdp->p, j, &rkey, &rdata, pgno,flags);
	}

	free(copy);
	return rc;
}

int
mdb_put(MDB_txn *txn, MDB_dbi dbi,
    MDB_val *key, MDB_val *data, unsigned int flags)
{
	int		 rc = MDB_SUCCESS, exact;
	unsigned int	 ki;
	MDB_node	*leaf;
	MDB_pageparent	mpp;

	assert(key != NULL);
	assert(data != NULL);

	if (txn == NULL)
		return EINVAL;

	if (F_ISSET(txn->mt_flags, MDB_TXN_RDONLY)) {
		return EINVAL;
	}

	if (txn->mt_env->me_txn != txn) {
		return EINVAL;
	}

	if (key->mv_size == 0 || key->mv_size > MAXKEYSIZE) {
		return EINVAL;
	}

	DPRINTF("==> put key %.*s, size %zu, data size %zu",
		(int)key->mv_size, (char *)key->mv_data, key->mv_size, data->mv_size);

	rc = mdb_search_page(txn, dbi, key, NULL, 1, &mpp);
	if (rc == MDB_SUCCESS) {
		leaf = mdb_search_node(txn, dbi, mpp.mp_page, key, &exact, &ki);
		if (leaf && exact) {
			if (F_ISSET(flags, MDB_NOOVERWRITE)) {
				DPRINTF("duplicate key %.*s",
				    (int)key->mv_size, (char *)key->mv_data);
				return EEXIST;
			}
			mdb_del_node(mpp.mp_page, ki);
		}
		if (leaf == NULL) {		/* append if not found */
			ki = NUMKEYS(mpp.mp_page);
			DPRINTF("appending key at index %i", ki);
		}
	} else if (rc == ENOENT) {
		MDB_dpage *dp;
		/* new file, just write a root leaf page */
		DPRINTF("allocating new root leaf page");
		if ((dp = mdb_new_page(txn, dbi, P_LEAF, 1)) == NULL) {
			return ENOMEM;
		}
		mpp.mp_page = &dp->p;
		txn->mt_dbs[dbi]->md_root = mpp.mp_page->mp_pgno;
		txn->mt_dbs[dbi]->md_depth++;
		ki = 0;
	}
	else
		goto done;

	assert(IS_LEAF(mpp.mp_page));
	DPRINTF("there are %u keys, should insert new key at index %i",
		NUMKEYS(mpp.mp_page), ki);

	if (SIZELEFT(mpp.mp_page) < mdb_leaf_size(txn->mt_env, key, data)) {
		rc = mdb_split(txn, dbi, &mpp.mp_page, &ki, key, data, P_INVALID);
	} else {
		/* There is room already in this leaf page. */
		rc = mdb_add_node(txn, dbi, mpp.mp_page, ki, key, data, 0, 0);
	}

	if (rc != MDB_SUCCESS)
		txn->mt_flags |= MDB_TXN_ERROR;
	else
		txn->mt_dbs[dbi]->md_entries++;

done:
	return rc;
}

int
mdbenv_get_flags(MDB_env *env, unsigned int *arg)
{
	if (!env || !arg)
		return EINVAL;

	*arg = env->me_flags;
	return MDB_SUCCESS;
}

int
mdbenv_get_path(MDB_env *env, const char **arg)
{
	if (!env || !arg)
		return EINVAL;

	*arg = env->me_path;
	return MDB_SUCCESS;
}

int
mdbenv_stat(MDB_env *env, MDB_stat *arg)
{
	if (env == NULL || arg == NULL)
		return EINVAL;

	arg->ms_psize = env->me_meta.mm_psize;
	arg->ms_depth = env->me_meta.mm_depth;
	arg->ms_branch_pages = env->me_meta.mm_branch_pages;
	arg->ms_leaf_pages = env->me_meta.mm_leaf_pages;
	arg->ms_overflow_pages = env->me_meta.mm_overflow_pages;
	arg->ms_entries = env->me_meta.mm_entries;

	return MDB_SUCCESS;
}

int mdb_open(MDB_txn *txn, const char *name, unsigned int flags, MDB_dbi *dbi)
{
	MDB_val key, data;
	MDB_dbi i;
	int rc;

	/* main DB? */
	if (!name) {
		*dbi = 0;
		return MDB_SUCCESS;
	}

	/* Is the DB already open? */
	for (i=0; i<txn->mt_numdbs; i++) {
		if (!strcmp(name, txn->mt_dbxs[i].md_name)) {
			*dbi = i;
			return MDB_SUCCESS;
		}
	}

	/* Find the DB info */
	key.mv_size = strlen(name);
	key.mv_data = (void *)name;
	rc = mdb_get(txn, 0, &key, &data);

	/* Create if requested */
	if (rc == ENOENT && (flags & MDB_CREATE)) {
		MDB_db dummy;
		data.mv_size = sizeof(MDB_db);
		data.mv_data = &dummy;
		memset(&dummy, 0, sizeof(dummy));
		dummy.md_root = P_INVALID;
		rc = mdb_put(txn, 0, &key, &data, 0);
		if (rc == MDB_SUCCESS)
			rc = mdb_get(txn, 0, &key, &data);
	}

	/* OK, got info, add to table */
	if (rc == MDB_SUCCESS) {
		/* Is there a free slot? */
		if ((txn->mt_numdbs & (DBX_CHUNK-1)) == 0) {
			MDB_dbx *p1;
			MDB_db **p2;
			int i;
			i = txn->mt_numdbs + DBX_CHUNK;
			p1 = realloc(txn->mt_dbxs, i * sizeof(MDB_dbx));
			if (p1 == NULL)
				return ENOMEM;
			txn->mt_dbxs = p1;
			p2 = realloc(txn->mt_dbs, i * sizeof(MDB_db *));
			if (p2 == NULL)
				return ENOMEM;
			txn->mt_dbs = p2;
		}
		txn->mt_dbxs[txn->mt_numdbs].md_name = strdup(name);
		txn->mt_dbxs[txn->mt_numdbs].md_cmp = NULL;
		txn->mt_dbxs[txn->mt_numdbs].md_rel = NULL;
		txn->mt_dbs[txn->mt_numdbs] = data.mv_data;
		*dbi = txn->mt_numdbs;
		txn->mt_numdbs++;
	}

	return rc;
}

int mdb_stat(MDB_txn *txn, MDB_dbi dbi, MDB_stat *arg)
{
	if (txn == NULL || arg == NULL)
		return EINVAL;

	arg->ms_psize = txn->mt_env->me_meta.mm_psize;
	arg->ms_depth = txn->mt_dbs[dbi]->md_depth;
	arg->ms_branch_pages = txn->mt_dbs[dbi]->md_branch_pages;
	arg->ms_leaf_pages = txn->mt_dbs[dbi]->md_leaf_pages;
	arg->ms_overflow_pages = txn->mt_dbs[dbi]->md_overflow_pages;
	arg->ms_entries = txn->mt_dbs[dbi]->md_entries;

	return MDB_SUCCESS;
}

void mdb_close(MDB_txn *txn, MDB_dbi dbi)
{
	if (dbi >= txn->mt_numdbs)
		return;
	free(txn->mt_dbxs[dbi].md_name);
	txn->mt_dbxs[dbi].md_name = NULL;
}
