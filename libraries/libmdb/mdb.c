#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/mman.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#include <sys/ipc.h>
#include <sys/shm.h>

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

#define DEBUG

#ifdef DEBUG
# define DPRINTF(...)	do { fprintf(stderr, "%s:%d: ", __func__, __LINE__); \
			     fprintf(stderr, __VA_ARGS__); \
			     fprintf(stderr, "\n"); } while(0)
#else
# define DPRINTF(...)
#endif

#define PAGESIZE	 4096
#define MDB_MINKEYS	 4
#define MDB_MAGIC	 0xBEEFC0DE
#define MDB_VERSION	 1
#define MAXKEYSIZE	 255

#define P_INVALID	 (~0L)

#define F_ISSET(w, f)	 (((w) & (f)) == (f))

typedef ulong		 pgno_t;
typedef uint16_t	 indx_t;

#define DEFAULT_READERS	126
#define DEFAULT_MAPSIZE	1048576

/* Lock descriptor stuff */
#define RXBODY	\
	ulong		mr_txnid; \
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
	ulong		mt_txnid;	\
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
#define	P_HEAD		 0x10		/* header page */
#define	P_DIRTY		 0x20		/* dirty page */
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

#define PAGEHDRSZ	 offsetof(MDB_page, mp_ptrs)

#define NUMKEYS(p)	 (((p)->mp_lower - PAGEHDRSZ) >> 1)
#define SIZELEFT(p)	 (indx_t)((p)->mp_upper - (p)->mp_lower)
#define PAGEFILL(env, p) (1000 * ((env)->me_head.mh_psize - PAGEHDRSZ - SIZELEFT(p)) / \
				((env)->me_head.mh_psize - PAGEHDRSZ))
#define IS_LEAF(p)	 F_ISSET((p)->mp_flags, P_LEAF)
#define IS_BRANCH(p)	 F_ISSET((p)->mp_flags, P_BRANCH)
#define IS_OVERFLOW(p)	 F_ISSET((p)->mp_flags, P_OVERFLOW)

typedef struct MDB_head {			/* header page content */
	uint32_t	mh_magic;
	uint32_t	mh_version;
	uint32_t	mh_flags;
	uint32_t	mh_psize;			/* page size */
	void		*mh_address;		/* address for fixed mapping */
	size_t		mh_mapsize;			/* size of mmap region */
} MDB_head;

typedef struct MDB_meta {			/* meta (footer) page content */
	MDB_stat	mm_stat;
	pgno_t		mm_root;			/* page number of root page */
	pgno_t		mm_last_pg;			/* last used page in file */
	ulong		mm_txnid;			/* txnid that committed this page */
} MDB_meta;

typedef struct MDB_dhead {					/* a dirty page */
	SIMPLEQ_ENTRY(MDB_dpage)	 md_next;	/* queue of dirty pages */
	MDB_page	*md_parent;
	int			md_pi;				/* parent index */
	int			md_num;
} MDB_dhead;

typedef struct MDB_dpage {
	MDB_dhead	h;
	MDB_page	p;
} MDB_dpage;

SIMPLEQ_HEAD(dirty_queue, MDB_dpage);

typedef struct MDB_pageparent {
	MDB_page *mp_page;
	MDB_page *mp_parent;
	int		mp_pi;
} MDB_pageparent;

static MDB_dpage *mdb_newpage(MDB_txn *txn, MDB_page *parent, int parent_idx, int num);
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
	MDB_db		*mc_db;
	MDB_txn		*mc_txn;
	struct page_stack	 mc_stack;		/* stack of parent pages */
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

struct MDB_txn {
	pgno_t		mt_root;		/* current / new root page */
	pgno_t		mt_next_pgno;	/* next unallocated page */
	pgno_t		mt_first_pgno;
	ulong		mt_txnid;
	MDB_env		*mt_env;	
	union {
		struct dirty_queue	*dirty_queue;	/* modified pages */
		MDB_reader	*reader;
	} mt_u;
#define MDB_TXN_RDONLY		 0x01		/* read-only transaction */
#define MDB_TXN_ERROR		 0x02		/* an error has occurred */
	unsigned int		 mt_flags;
};

/* Must be same as MDB_db, minus md_root/md_stat */
typedef struct MDB_db0 {
	unsigned int	md_flags;
	MDB_cmp_func	*md_cmp;		/* user compare function */
	MDB_rel_func	*md_rel;		/* user relocate function */
	MDB_db			*md_parent;		/* parent tree */
	MDB_env 		*md_env;
} MDB_db0;

struct MDB_db {
	unsigned int	md_flags;
	MDB_cmp_func	*md_cmp;		/* user compare function */
	MDB_rel_func	*md_rel;		/* user relocate function */
	MDB_db			*md_parent;		/* parent tree */
	MDB_env 		*md_env;
	MDB_stat		md_stat;
	pgno_t			md_root;		/* page number of root page */
};

struct MDB_env {
	int			me_fd;
	key_t		me_shmkey;
	uint32_t	me_flags;
	int			me_maxreaders;
	int			me_metatoggle;
	char		*me_path;
	char *me_map;
	MDB_txninfo	*me_txns;
	MDB_head	me_head;
	MDB_db0		me_db;		/* first DB, overlaps with meta */
	MDB_meta	me_meta;
	MDB_txn	*me_txn;		/* current write transaction */
	size_t		me_mapsize;
	off_t		me_size;		/* current file size */
	pthread_key_t	me_txkey;	/* thread-key for readers */
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

static int  mdb_search_page_root(MDB_db *db,
			    MDB_val *key,
			    MDB_cursor *cursor, int modify,
			    MDB_pageparent *mpp);
static int  mdb_search_page(MDB_db *db,
			    MDB_txn *txn, MDB_val *key,
			    MDB_cursor *cursor, int modify,
			    MDB_pageparent *mpp);

static int  mdbenv_write_header(MDB_env *env);
static int  mdbenv_read_header(MDB_env *env);
static int  mdb_check_meta_page(MDB_page *p);
static int  mdbenv_read_meta(MDB_env *env);
static int  mdbenv_write_meta(MDB_txn *txn);
static MDB_page *mdbenv_get_page(MDB_env *env, pgno_t pgno);

static MDB_node *mdb_search_node(MDB_db *db, MDB_page *mp,
			    MDB_val *key, int *exactp, unsigned int *kip);
static int  mdb_add_node(MDB_db *bt, MDB_page *mp,
			    indx_t indx, MDB_val *key, MDB_val *data,
			    pgno_t pgno, uint8_t flags);
static void mdb_del_node(MDB_db *bt, MDB_page *mp,
			    indx_t indx);
static int  mdb_read_data(MDB_db *bt, MDB_page *mp,
			    MDB_node *leaf, MDB_val *data);

static int		 mdb_rebalance(MDB_db *bt, MDB_pageparent *mp);
static int		 mdb_update_key(MDB_db *bt, MDB_page *mp,
			    indx_t indx, MDB_val *key);
static int		 mdb_move_node(MDB_db *bt, 
				MDB_pageparent *src, indx_t srcindx,
				MDB_pageparent *dst, indx_t dstindx);
static int		 mdb_merge(MDB_db *bt, MDB_pageparent *src,
			    MDB_pageparent *dst);
static int		 mdb_split(MDB_db *bt, MDB_page **mpp,
			    unsigned int *newindxp, MDB_val *newkey,
			    MDB_val *newdata, pgno_t newpgno);
static MDB_dpage *mdbenv_new_page(MDB_env *env, uint32_t flags, int num);

static void		 cursor_pop_page(MDB_cursor *cursor);
static MDB_ppage *cursor_push_page(MDB_cursor *cursor,
			    MDB_page *mp);

static int		 mdb_set_key(MDB_db *bt, MDB_page *mp,
			    MDB_node *node, MDB_val *key);
static int		 mdb_sibling(MDB_cursor *cursor, int move_right);
static int		 mdb_cursor_next(MDB_cursor *cursor,
			    MDB_val *key, MDB_val *data);
static int		 mdb_cursor_set(MDB_cursor *cursor,
			    MDB_val *key, MDB_val *data, int *exactp);
static int		 mdb_cursor_first(MDB_cursor *cursor,
			    MDB_val *key, MDB_val *data);

static size_t		 mdb_leaf_size(MDB_db *bt, MDB_val *key,
			    MDB_val *data);
static size_t		 mdb_branch_size(MDB_db *bt, MDB_val *key);

static pgno_t		 mdbenv_compact_tree(MDB_env *env, pgno_t pgno,
			    MDB_env *envc);

static int		 memncmp(const void *s1, size_t n1,
				 const void *s2, size_t n2);
static int		 memnrcmp(const void *s1, size_t n1,
				  const void *s2, size_t n2);

static int
memncmp(const void *s1, size_t n1, const void *s2, size_t n2)
{
	if (n1 < n2) {
		if (memcmp(s1, s2, n1) == 0)
			return -1;
	}
	else if (n1 > n2) {
		if (memcmp(s1, s2, n2) == 0)
			return 1;
	}
	return memcmp(s1, s2, n1);
}

static int
memnrcmp(const void *s1, size_t n1, const void *s2, size_t n2)
{
	const unsigned char	*p1;
	const unsigned char	*p2;

	if (n1 == 0)
		return n2 == 0 ? 0 : -1;

	if (n2 == 0)
		return n1 == 0 ? 0 : 1;

	p1 = (const unsigned char *)s1 + n1 - 1;
	p2 = (const unsigned char *)s2 + n2 - 1;

	while (*p1 == *p2) {
		if (p1 == s1)
			return (p2 == s2) ? 0 : -1;
		if (p2 == s2)
			return (p1 == p2) ? 0 : 1;
		p1--;
		p2--;
	}
	return *p1 - *p2;
}

int
mdb_cmp(MDB_db *db, const MDB_val *a, const MDB_val *b)
{
	return db->md_cmp(a, b);
}

static int
_mdb_cmp(MDB_db *db, const MDB_val *key1, const MDB_val *key2)
{
	if (F_ISSET(db->md_flags, MDB_REVERSEKEY))
		return memnrcmp(key1->mv_data, key1->mv_size, key2->mv_data, key2->mv_size);
	else
		return memncmp((char *)key1->mv_data, key1->mv_size, key2->mv_data, key2->mv_size);
}

/* Allocate new page(s) for writing */
static MDB_dpage *
mdb_newpage(MDB_txn *txn, MDB_page *parent, int parent_idx, int num)
{
	MDB_dpage *dp;

	if ((dp = malloc(txn->mt_env->me_head.mh_psize * num + sizeof(MDB_dhead))) == NULL)
		return NULL;
	dp->h.md_num = num;
	dp->h.md_parent = parent;
	dp->h.md_pi = parent_idx;
	SIMPLEQ_INSERT_TAIL(txn->mt_u.dirty_queue, dp, h.md_next);
	dp->p.mp_pgno = txn->mt_next_pgno;
	txn->mt_next_pgno += num;

	return dp;
}

/* Touch a page: make it dirty and re-insert into tree with updated pgno.
 */
static int
mdb_touch(MDB_txn *txn, MDB_pageparent *pp)
{
	int rc;
	MDB_page *mp = pp->mp_page;
	pgno_t	pgno;
	assert(txn != NULL);
	assert(pp != NULL);

	if (!F_ISSET(mp->mp_flags, P_DIRTY)) {
		MDB_dpage *dp;
		DPRINTF("touching page %lu -> %lu", mp->mp_pgno, txn->mt_next_pgno);
		if ((dp = mdb_newpage(txn, pp->mp_parent, pp->mp_pi, 1)) == NULL)
			return ENOMEM;
		pgno = dp->p.mp_pgno;
		bcopy(mp, &dp->p, txn->mt_env->me_head.mh_psize);
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

int
mdb_txn_begin(MDB_env *env, int rdonly, MDB_txn **ret)
{
	MDB_txn	*txn;
	int rc;

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
	}
	txn->mt_txnid = env->me_txns->mt_txnid;
	if (rdonly) {
		MDB_reader *r = pthread_getspecific(env->me_txkey);
		if (!r) {
			int i;
			pthread_mutex_lock(&env->me_txns->mt_mutex);
			for (i=0; i<env->me_maxreaders; i++) {
				if (env->me_txns->mt_readers[i].mr_pid == 0) {
					env->me_txns->mt_readers[i].mr_pid = getpid();
					env->me_txns->mt_readers[i].mr_tid = pthread_self();
					pthread_setspecific(env->me_txkey, &env->me_txns->mt_readers[i]);
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

	if ((rc = mdbenv_read_meta(env)) != MDB_SUCCESS) {
		mdb_txn_abort(txn);
		return rc;
	}

	txn->mt_next_pgno = env->me_meta.mm_last_pg+1;
	txn->mt_first_pgno = txn->mt_next_pgno;
	txn->mt_root = env->me_meta.mm_root;
	DPRINTF("begin transaction %lu on mdbenv %p, root page %lu", txn->mt_txnid, env, txn->mt_root);

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
	DPRINTF("abort transaction %lu on mdbenv %p, root page %lu", txn->mt_txnid, env, txn->mt_root);

	if (F_ISSET(txn->mt_flags, MDB_TXN_RDONLY)) {
		txn->mt_u.reader->mr_txnid = 0;
	} else {
		/* Discard all dirty pages.
		 */
		while (!SIMPLEQ_EMPTY(txn->mt_u.dirty_queue)) {
			dp = SIMPLEQ_FIRST(txn->mt_u.dirty_queue);
			SIMPLEQ_REMOVE_HEAD(txn->mt_u.dirty_queue, h.md_next);
			free(dp);
		}

#if 0
		DPRINTF("releasing write lock on txn %p", txn);
		txn->bt->txn = NULL;
		if (flock(txn->bt->fd, LOCK_UN) != 0) {
			DPRINTF("failed to unlock fd %d: %s",
			    txn->bt->fd, strerror(errno));
		}
#endif
		free(txn->mt_u.dirty_queue);
		env->me_txn = NULL;
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
	    txn->mt_txnid, env, txn->mt_root);

	/* Commit up to MDB_COMMIT_PAGES dirty pages to disk until done.
	 */
	next = 0;
	do {
		n = 0;
		done = 1;
		size = 0;
		SIMPLEQ_FOREACH(dp, txn->mt_u.dirty_queue, h.md_next) {
			if (dp->p.mp_pgno != next) {
				lseek(env->me_fd, dp->p.mp_pgno * env->me_head.mh_psize, SEEK_SET);
				next = dp->p.mp_pgno;
				if (n)
					break;
			}
			DPRINTF("committing page %lu", dp->p.mp_pgno);
			iov[n].iov_len = env->me_head.mh_psize * dp->h.md_num;
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

		/* Drop the dirty pages.
		 */
		while (!SIMPLEQ_EMPTY(txn->mt_u.dirty_queue)) {
			dp = SIMPLEQ_FIRST(txn->mt_u.dirty_queue);
			SIMPLEQ_REMOVE_HEAD(txn->mt_u.dirty_queue, h.md_next);
			free(dp);
			if (--n == 0)
				break;
		}
	} while (!done);

	if ((n = mdbenv_sync(env)) != 0 ||
	    (n = mdbenv_write_meta(txn)) != MDB_SUCCESS ||
	    (n = mdbenv_sync(env)) != 0) {
		mdb_txn_abort(txn);
		return n;
	}
	env->me_txn = NULL;
	pthread_mutex_unlock(&env->me_txns->mt_wmutex);
	free(txn->mt_u.dirty_queue);
	free(txn);
	txn = NULL;

done:
	mdb_txn_abort(txn);

	return MDB_SUCCESS;
}

static int
mdbenv_write_header(MDB_env *env)
{
	struct stat	 sb;
	MDB_head	*h;
	MDB_page	*p;
	ssize_t		 rc;
	unsigned int	 psize;

	DPRINTF("writing header page");
	assert(env != NULL);

	psize = sysconf(_SC_PAGE_SIZE);

	if ((p = calloc(1, psize)) == NULL)
		return ENOMEM;
	p->mp_flags = P_HEAD;

	env->me_head.mh_psize = psize;
	env->me_head.mh_flags = env->me_flags & 0xffff;

	h = METADATA(p);
	bcopy(&env->me_head, h, sizeof(*h));

	rc = write(env->me_fd, p, env->me_head.mh_psize);
	free(p);
	if (rc != (ssize_t)env->me_head.mh_psize) {
		int err = errno;
		if (rc > 0)
			DPRINTF("short write, filesystem full?");
		return err;
	}

	return MDB_SUCCESS;
}

static int
mdbenv_read_header(MDB_env *env)
{
	char		 page[PAGESIZE];
	MDB_page	*p;
	MDB_head	*h;
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

	if (!F_ISSET(p->mp_flags, P_HEAD)) {
		DPRINTF("page %lu not a header page", p->mp_pgno);
		return EINVAL;
	}

	h = METADATA(p);
	if (h->mh_magic != MDB_MAGIC) {
		DPRINTF("header has invalid magic");
		return EINVAL;
	}

	if (h->mh_version != MDB_VERSION) {
		DPRINTF("database is version %u, expected version %u",
		    h->mh_version, MDB_VERSION);
		return EINVAL;
	}

	bcopy(h, &env->me_head, sizeof(*h));
	return 0;
}

static int
mdbenv_init_meta(MDB_env *env)
{
	MDB_page *p, *q;
	MDB_meta *meta;
	int rc;

	p = calloc(2, env->me_head.mh_psize);
	p->mp_pgno = 1;
	p->mp_flags = P_META;

	meta = METADATA(p);
	meta->mm_root = P_INVALID;
	meta->mm_last_pg = 2;

	q = (MDB_page *)((char *)p + env->me_head.mh_psize);

	q->mp_pgno = 2;
	q->mp_flags = P_META;

	meta = METADATA(q);
	meta->mm_root = P_INVALID;
	meta->mm_last_pg = 2;

	rc = write(env->me_fd, p, env->me_head.mh_psize * 2);
	free(p);
	return (rc == env->me_head.mh_psize * 2) ? MDB_SUCCESS : errno;
}

static int
mdbenv_write_meta(MDB_txn *txn)
{
	MDB_env *env;
	MDB_meta	meta;
	off_t off;
	int rc;

	assert(txn != NULL);
	assert(txn->mt_env != NULL);

	DPRINTF("writing meta page for root page %lu", txn->mt_root);

	env = txn->mt_env;

	bcopy(&env->me_meta, &meta, sizeof(meta));
	meta.mm_root = txn->mt_root;
	meta.mm_last_pg = txn->mt_next_pgno - 1;
	meta.mm_txnid = txn->mt_txnid;

	off = env->me_head.mh_psize;
	if (!env->me_metatoggle)
		off *= 2;
	off += PAGEHDRSZ;

	lseek(env->me_fd, off, SEEK_SET);
	rc = write(env->me_fd, &meta, sizeof(meta));
	if (rc != sizeof(meta)) {
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
mdbenv_read_meta(MDB_env *env)
{
	MDB_page	*mp0, *mp1;
	MDB_meta	*meta[2];
	int toggle = 0, rc;

	assert(env != NULL);

	if ((mp0 = mdbenv_get_page(env, 1)) == NULL ||
		(mp1 = mdbenv_get_page(env, 2)) == NULL)
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
		bcopy(meta[toggle], &env->me_meta, sizeof(env->me_meta));
		env->me_metatoggle = toggle;
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

	e->me_head.mh_magic = MDB_MAGIC;
	e->me_head.mh_version = MDB_VERSION;
	e->me_head.mh_mapsize = DEFAULT_MAPSIZE;
	e->me_maxreaders = DEFAULT_READERS;
	e->me_db.md_env = e;
	*env = e;
	return MDB_SUCCESS;
}

int
mdbenv_set_mapsize(MDB_env *env, size_t size)
{
	if (env->me_map)
		return EINVAL;
	env->me_mapsize = env->me_head.mh_mapsize = size;
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
	env->me_meta.mm_root = P_INVALID;
	env->me_meta.mm_last_pg = 2;

	if ((i = mdbenv_read_header(env)) != 0) {
		if (i != ENOENT)
			return i;
		DPRINTF("new mdbenv");
		newenv = 1;
	}

	if (!env->me_mapsize)
		env->me_mapsize = env->me_head.mh_mapsize;

	i = MAP_SHARED;
	if (env->me_head.mh_address && (flags & MDB_FIXEDMAP))
		i |= MAP_FIXED;
	env->me_map = mmap(env->me_head.mh_address, env->me_mapsize, PROT_READ, i,
		env->me_fd, 0);
	if (env->me_map == MAP_FAILED)
		return errno;

	if (newenv) {
		env->me_head.mh_mapsize = env->me_mapsize;
		if (flags & MDB_FIXEDMAP)
			env->me_head.mh_address = env->me_map;
		i = mdbenv_write_header(env);
		if (i != MDB_SUCCESS) {
			munmap(env->me_map, env->me_mapsize);
			return i;
		}
		i = mdbenv_init_meta(env);
		if (i != MDB_SUCCESS) {
			munmap(env->me_map, env->me_mapsize);
			return i;
		}
	}

	if ((i = mdbenv_read_meta(env)) != 0)
		return i;

	DPRINTF("opened database version %u, pagesize %u",
	    env->me_head.mh_version, env->me_head.mh_psize);
	DPRINTF("depth: %u", env->me_meta.mm_stat.ms_depth);
	DPRINTF("entries: %lu", env->me_meta.mm_stat.ms_entries);
	DPRINTF("branch pages: %lu", env->me_meta.mm_stat.ms_branch_pages);
	DPRINTF("leaf pages: %lu", env->me_meta.mm_stat.ms_leaf_pages);
	DPRINTF("overflow pages: %lu", env->me_meta.mm_stat.ms_overflow_pages);
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

int
mdbenv_open(MDB_env *env, const char *path, unsigned int flags, mode_t mode)
{
	int		oflags, rc, shmid;
	off_t	size;


	if (F_ISSET(flags, MDB_RDONLY))
		oflags = O_RDONLY;
	else
		oflags = O_RDWR | O_CREAT;

	if ((env->me_fd = open(path, oflags, mode)) == -1)
		return errno;

	env->me_shmkey = ftok(path, 'm');
	size = (env->me_maxreaders-1) * sizeof(MDB_reader) + sizeof(MDB_txninfo);
	shmid = shmget(env->me_shmkey, size, IPC_CREAT|IPC_EXCL|mode);
	if (shmid == -1) {
		if (errno == EEXIST) {
			shmid = shmget(env->me_shmkey, size, IPC_CREAT|mode);
			if (shmid == -1)
				return errno;
			env->me_txns = shmat(shmid, NULL, 0);
			if (env->me_txns->mt_magic != MDB_MAGIC ||
				env->me_txns->mt_version != MDB_VERSION) {
					DPRINTF("invalid lock region %d", shmid);
					shmdt(env->me_txns);
					env->me_txns = NULL;
					return EIO;
				}
		} else {
			return errno;
		}
	} else {
		pthread_mutexattr_t mattr;

		env->me_txns = shmat(shmid, NULL, 0);
		pthread_mutexattr_init(&mattr);
		pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
		pthread_mutex_init(&env->me_txns->mt_mutex, &mattr);
		pthread_mutex_init(&env->me_txns->mt_wmutex, &mattr);
		env->me_txns->mt_version = MDB_VERSION;
		env->me_txns->mt_magic = MDB_MAGIC;
	}

	if ((rc = mdbenv_open2(env, flags)) != MDB_SUCCESS) {
		close(env->me_fd);
		env->me_fd = -1;
	} else {
		env->me_path = strdup(path);
		DPRINTF("opened dbenv %p", env);
	}

	pthread_key_create(&env->me_txkey, mdbenv_reader_dest);

	return rc;
}

void
mdbenv_close(MDB_env *env)
{
	if (env == NULL)
		return;

	free(env->me_path);

	if (env->me_map) {
		munmap(env->me_map, env->me_mapsize);
	}
	close(env->me_fd);
	if (env->me_txns) {
		shmdt(env->me_txns);
	}
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
mdb_search_node(MDB_db *bt, MDB_page *mp, MDB_val *key,
    int *exactp, unsigned int *kip)
{
	unsigned int	 i = 0;
	int		 low, high;
	int		 rc = 0;
	MDB_node	*node;
	MDB_val	 nodekey;

	DPRINTF("searching %lu keys in %s page %lu",
	    NUMKEYS(mp),
	    IS_LEAF(mp) ? "leaf" : "branch",
	    mp->mp_pgno);

	assert(NUMKEYS(mp) > 0);

	bzero(&nodekey, sizeof(nodekey));

	low = IS_LEAF(mp) ? 0 : 1;
	high = NUMKEYS(mp) - 1;
	while (low <= high) {
		i = (low + high) >> 1;
		node = NODEPTR(mp, i);

		nodekey.mv_size = node->mn_ksize;
		nodekey.mv_data = NODEKEY(node);

		if (bt->md_cmp)
			rc = bt->md_cmp(key, &nodekey);
		else
			rc = _mdb_cmp(bt, key, &nodekey);

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

	DPRINTF("popped page %lu off cursor %p", top->mp_page->mp_pgno, cursor);

	free(top);
}

static MDB_ppage *
cursor_push_page(MDB_cursor *cursor, MDB_page *mp)
{
	MDB_ppage	*ppage;

	DPRINTF("pushing page %lu on cursor %p", mp->mp_pgno, cursor);

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

	if (txn && pgno >= txn->mt_first_pgno &&
		!SIMPLEQ_EMPTY(txn->mt_u.dirty_queue)) {
		MDB_dpage *dp;
		SIMPLEQ_FOREACH(dp, txn->mt_u.dirty_queue, h.md_next) {
			if (dp->p.mp_pgno == pgno) {
				p = &dp->p;
				break;
			}
		}
	} else {
		p = (MDB_page *)(env->me_map + env->me_head.mh_psize * pgno);
	}
	return p;
}

static int
mdb_search_page_root(MDB_db *bt, MDB_val *key,
    MDB_cursor *cursor, int modify, MDB_pageparent *mpp)
{
	MDB_page	*mp = mpp->mp_page;
	int rc;

	if (cursor && cursor_push_page(cursor, mp) == NULL)
		return MDB_FAIL;

	while (IS_BRANCH(mp)) {
		unsigned int	 i = 0;
		MDB_node	*node;

		DPRINTF("branch page %lu has %lu keys", mp->mp_pgno, NUMKEYS(mp));
		assert(NUMKEYS(mp) > 1);
		DPRINTF("found index 0 to page %lu", NODEPGNO(NODEPTR(mp, 0)));

		if (key == NULL)	/* Initialize cursor to first page. */
			i = 0;
		else {
			int	 exact;
			node = mdb_search_node(bt, mp, key, &exact, &i);
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
		assert(i >= 0 && i < NUMKEYS(mp));
		node = NODEPTR(mp, i);

		if (cursor)
			CURSOR_TOP(cursor)->mp_ki = i;

		mpp->mp_parent = mp;
		if ((mp = mdbenv_get_page(bt->md_env, NODEPGNO(node))) == NULL)
			return MDB_FAIL;
		mpp->mp_pi = i;
		mpp->mp_page = mp;

		if (cursor && cursor_push_page(cursor, mp) == NULL)
			return MDB_FAIL;

		if (modify) {
			MDB_dhead *dh = ((MDB_dhead *)mp)-1;
			if (rc = mdb_touch(bt->md_env->me_txn, mpp))
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
mdb_search_page(MDB_db *db, MDB_txn *txn, MDB_val *key,
    MDB_cursor *cursor, int modify, MDB_pageparent *mpp)
{
	int		 rc;
	pgno_t		 root;

	/* Can't modify pages outside a transaction. */
	if (txn == NULL && modify) {
		return EINVAL;
	}

	/* Choose which root page to start with. If a transaction is given
	 * use the root page from the transaction, otherwise read the last
	 * committed root page.
	 */
	if (txn == NULL) {
		if ((rc = mdbenv_read_meta(db->md_env)) != MDB_SUCCESS)
			return rc;
		root = db->md_env->me_meta.mm_root;
	} else if (F_ISSET(txn->mt_flags, MDB_TXN_ERROR)) {
		DPRINTF("transaction has failed, must abort");
		return EINVAL;
	} else
		root = txn->mt_root;

	if (root == P_INVALID) {		/* Tree is empty. */
		DPRINTF("tree is empty");
		return ENOENT;
	}

	if ((mpp->mp_page = mdbenv_get_page(db->md_env, root)) == NULL)
		return MDB_FAIL;

	DPRINTF("root page has flags 0x%X", mpp->mp_page->mp_flags);

	if (modify && !F_ISSET(mpp->mp_page->mp_flags, P_DIRTY)) {
		mpp->mp_parent = NULL;
		mpp->mp_pi = 0;
		if ((rc = mdb_touch(txn, mpp)))
			return rc;
		txn->mt_root = mpp->mp_page->mp_pgno;
	}

	return mdb_search_page_root(db, key, cursor, modify, mpp);
}

static int
mdb_read_data(MDB_db *db, MDB_page *mp, MDB_node *leaf,
    MDB_val *data)
{
	MDB_page	*omp;		/* overflow mpage */
	size_t		 psz;
	size_t		 max;
	size_t		 sz = 0;
	pgno_t		 pgno;

	bzero(data, sizeof(*data));
	max = db->md_env->me_head.mh_psize - PAGEHDRSZ;

	if (!F_ISSET(leaf->mn_flags, F_BIGDATA)) {
		data->mv_size = leaf->mn_dsize;
		data->mv_data = NODEDATA(leaf);
		return MDB_SUCCESS;
	}

	/* Read overflow data.
	 */
	data->mv_size = leaf->mn_dsize;
	bcopy(NODEDATA(leaf), &pgno, sizeof(pgno));
	if ((omp = mdbenv_get_page(db->md_env, pgno)) == NULL) {
		DPRINTF("read overflow page %lu failed", pgno);
		return MDB_FAIL;
	}
	data->mv_data = omp;

	return MDB_SUCCESS;
}

int
mdb_get(MDB_db *db, MDB_txn *txn,
    MDB_val *key, MDB_val *data)
{
	int		 rc, exact;
	MDB_node	*leaf;
	MDB_pageparent mpp;

	assert(key);
	assert(data);
	DPRINTF("===> get key [%.*s]", (int)key->mv_size, (char *)key->mv_data);

	if (db == NULL)
		return EINVAL;

	if (txn != NULL && db->md_env != txn->mt_env) {
		return EINVAL;
	}

	if (key->mv_size == 0 || key->mv_size > MAXKEYSIZE) {
		return EINVAL;
	}

	if ((rc = mdb_search_page(db, txn, key, NULL, 0, &mpp)) != MDB_SUCCESS)
		return rc;

	leaf = mdb_search_node(db, mpp.mp_page, key, &exact, NULL);
	if (leaf && exact)
		rc = mdb_read_data(db, mpp.mp_page, leaf, data);
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
	if ((mp = mdbenv_get_page(cursor->mc_db->md_env, indx->mn_pgno)) == NULL)
		return MDB_FAIL;
#if 0
	mp->parent = parent->mp_page;
	mp->parent_index = parent->mp_ki;
#endif

	cursor_push_page(cursor, mp);

	return MDB_SUCCESS;
}

static int
mdb_set_key(MDB_db *bt, MDB_page *mp, MDB_node *node,
    MDB_val *key)
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

	DPRINTF("cursor_next: top page is %lu in cursor %p", mp->mp_pgno, cursor);

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

	DPRINTF("==> cursor points to page %lu with %lu keys, key index %u",
	    mp->mp_pgno, NUMKEYS(mp), top->mp_ki);

	assert(IS_LEAF(mp));
	leaf = NODEPTR(mp, top->mp_ki);

	if (data && mdb_read_data(cursor->mc_db, mp, leaf, data) != MDB_SUCCESS)
		return MDB_FAIL;

	return mdb_set_key(cursor->mc_db, mp, leaf, key);
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

	rc = mdb_search_page(cursor->mc_db, cursor->mc_txn, key, cursor, 0, &mpp);
	if (rc != MDB_SUCCESS)
		return rc;
	assert(IS_LEAF(mpp.mp_page));

	top = CURSOR_TOP(cursor);
	leaf = mdb_search_node(cursor->mc_db, mpp.mp_page, key, exactp, &top->mp_ki);
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

	if (data && (rc = mdb_read_data(cursor->mc_db, mpp.mp_page, leaf, data)) != MDB_SUCCESS)
		return rc;

	rc = mdb_set_key(cursor->mc_db, mpp.mp_page, leaf, key);
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

	rc = mdb_search_page(cursor->mc_db, cursor->mc_txn, NULL, cursor, 0, &mpp);
	if (rc != MDB_SUCCESS)
		return rc;
	assert(IS_LEAF(mpp.mp_page));

	leaf = NODEPTR(mpp.mp_page, 0);
	cursor->mc_initialized = 1;
	cursor->mc_eof = 0;

	if (data && (rc = mdb_read_data(cursor->mc_db, mpp.mp_page, leaf, data)) != MDB_SUCCESS)
		return rc;

	return mdb_set_key(cursor->mc_db, mpp.mp_page, leaf, key);
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
mdbenv_new_page(MDB_env *env, uint32_t flags, int num)
{
	MDB_dpage	*dp;

	assert(env != NULL);
	assert(env->me_txn != NULL);

	DPRINTF("allocating new mpage %lu, page size %u",
	    env->me_txn->mt_next_pgno, env->me_head.mh_psize);
	if ((dp = mdb_newpage(env->me_txn, NULL, 0, num)) == NULL)
		return NULL;
	dp->p.mp_flags = flags | P_DIRTY;
	dp->p.mp_lower = PAGEHDRSZ;
	dp->p.mp_upper = env->me_head.mh_psize;

	if (IS_BRANCH(&dp->p))
		env->me_meta.mm_stat.ms_branch_pages++;
	else if (IS_LEAF(&dp->p))
		env->me_meta.mm_stat.ms_leaf_pages++;
	else if (IS_OVERFLOW(&dp->p)) {
		env->me_meta.mm_stat.ms_overflow_pages += num;
		dp->p.mp_pages = num;
	}

	return dp;
}

static size_t
mdb_leaf_size(MDB_db *db, MDB_val *key, MDB_val *data)
{
	size_t		 sz;

	sz = LEAFSIZE(key, data);
	if (data->mv_size >= db->md_env->me_head.mh_psize / MDB_MINKEYS) {
		/* put on overflow page */
		sz -= data->mv_size - sizeof(pgno_t);
	}

	return sz + sizeof(indx_t);
}

static size_t
mdb_branch_size(MDB_db *db, MDB_val *key)
{
	size_t		 sz;

	sz = INDXSIZE(key);
	if (sz >= db->md_env->me_head.mh_psize / MDB_MINKEYS) {
		/* put on overflow page */
		/* not implemented */
		/* sz -= key->size - sizeof(pgno_t); */
	}

	return sz + sizeof(indx_t);
}

static int
mdb_add_node(MDB_db *db, MDB_page *mp, indx_t indx,
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
		} else if (data->mv_size >= db->md_env->me_head.mh_psize / MDB_MINKEYS) {
			int ovpages = PAGEHDRSZ + data->mv_size + db->md_env->me_head.mh_psize - 1;
			ovpages /= db->md_env->me_head.mh_psize;
			/* Put data on overflow page. */
			DPRINTF("data size is %zu, put on overflow page",
			    data->mv_size);
			node_size += sizeof(pgno_t);
			if ((ofp = mdbenv_new_page(db->md_env, P_OVERFLOW, ovpages)) == NULL)
				return MDB_FAIL;
			DPRINTF("allocated overflow page %lu", ofp->p.mp_pgno);
			flags |= F_BIGDATA;
		} else {
			node_size += data->mv_size;
		}
	}

	if (node_size + sizeof(indx_t) > SIZELEFT(mp)) {
		DPRINTF("not enough room in page %lu, got %lu ptrs",
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
		bcopy(key->mv_data, NODEKEY(node), key->mv_size);

	if (IS_LEAF(mp)) {
		assert(key);
		if (ofp == NULL) {
			if (F_ISSET(flags, F_BIGDATA))
				bcopy(data->mv_data, node->mn_data + key->mv_size,
				    sizeof(pgno_t));
			else
				bcopy(data->mv_data, node->mn_data + key->mv_size,
				    data->mv_size);
		} else {
			bcopy(&ofp->p.mp_pgno, node->mn_data + key->mv_size,
			    sizeof(pgno_t));
			bcopy(data->mv_data, METADATA(&ofp->p), data->mv_size);
		}
	}

	return MDB_SUCCESS;
}

static void
mdb_del_node(MDB_db *db, MDB_page *mp, indx_t indx)
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
	bcopy(base, base + sz, ptr - mp->mp_upper);

	mp->mp_lower -= sizeof(indx_t);
	mp->mp_upper += sz;
}

int
mdb_cursor_open(MDB_db *db, MDB_txn *txn, MDB_cursor **ret)
{
	MDB_cursor	*cursor;

	if (db == NULL || ret == NULL)
		return EINVAL;

	if (txn != NULL && db->md_env != txn->mt_env) {
		return EINVAL;
	}

	if ((cursor = calloc(1, sizeof(*cursor))) != NULL) {
		SLIST_INIT(&cursor->mc_stack);
		cursor->mc_db = db;
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
mdb_update_key(MDB_db *db, MDB_page *mp, indx_t indx,
    MDB_val *key)
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
		bcopy(base, base - delta, len);
		mp->mp_upper -= delta;

		node = NODEPTR(mp, indx);
		node->mn_ksize = key->mv_size;
	}

	bcopy(key->mv_data, NODEKEY(node), key->mv_size);

	return MDB_SUCCESS;
}

/* Move a node from src to dst.
 */
static int
mdb_move_node(MDB_db *bt, MDB_pageparent *src, indx_t srcindx,
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
	if ((rc = mdb_touch(bt->md_env->me_txn, src)) ||
	    (rc = mdb_touch(bt->md_env->me_txn, dst)))
		return rc;;

	/* Add the node to the destination page.
	 */
	key.mv_size = srcnode->mn_ksize;
	key.mv_data = NODEKEY(srcnode);
	data.mv_size = NODEDSZ(srcnode);
	data.mv_data = NODEDATA(srcnode);
	rc = mdb_add_node(bt, dst->mp_page, dstindx, &key, &data, NODEPGNO(srcnode),
	    srcnode->mn_flags);
	if (rc != MDB_SUCCESS)
		return rc;

	/* Delete the node from the source page.
	 */
	mdb_del_node(bt, src->mp_page, srcindx);

	/* Update the parent separators.
	 */
	if (srcindx == 0 && src->mp_pi != 0) {
		DPRINTF("update separator for source page %lu to [%.*s]",
		    src->mp_page->mp_pgno, (int)key.mv_size, (char *)key.mv_data);
		if ((rc = mdb_update_key(bt, src->mp_parent, src->mp_pi,
		    &key)) != MDB_SUCCESS)
			return rc;
	}

	if (srcindx == 0 && IS_BRANCH(src->mp_page)) {
		MDB_val	 nullkey;
		nullkey.mv_size = 0;
		assert(mdb_update_key(bt, src->mp_page, 0, &nullkey) == MDB_SUCCESS);
	}

	if (dstindx == 0 && dst->mp_pi != 0) {
		DPRINTF("update separator for destination page %lu to [%.*s]",
		    dst->mp_page->mp_pgno, (int)key.mv_size, (char *)key.mv_data);
		if ((rc = mdb_update_key(bt, dst->mp_parent, dst->mp_pi,
		    &key)) != MDB_SUCCESS)
			return rc;
	}

	if (dstindx == 0 && IS_BRANCH(dst->mp_page)) {
		MDB_val	 nullkey;
		nullkey.mv_size = 0;
		assert(mdb_update_key(bt, dst->mp_page, 0, &nullkey) == MDB_SUCCESS);
	}

	return MDB_SUCCESS;
}

static int
mdb_merge(MDB_db *bt, MDB_pageparent *src, MDB_pageparent *dst)
{
	int			 rc;
	indx_t			 i;
	MDB_node		*srcnode;
	MDB_val		 key, data;
	MDB_pageparent	mpp;
	MDB_dhead *dh;

	DPRINTF("merging page %lu and %lu", src->mp_page->mp_pgno, dst->mp_page->mp_pgno);

	assert(src->mp_parent);	/* can't merge root page */
	assert(dst->mp_parent);
	assert(bt->md_env->me_txn != NULL);

	/* Mark src and dst as dirty. */
	if ((rc = mdb_touch(bt->md_env->me_txn, src)) ||
	    (rc = mdb_touch(bt->md_env->me_txn, dst)))
		return rc;

	/* Move all nodes from src to dst.
	 */
	for (i = 0; i < NUMKEYS(src->mp_page); i++) {
		srcnode = NODEPTR(src->mp_page, i);

		key.mv_size = srcnode->mn_ksize;
		key.mv_data = NODEKEY(srcnode);
		data.mv_size = NODEDSZ(srcnode);
		data.mv_data = NODEDATA(srcnode);
		rc = mdb_add_node(bt, dst->mp_page, NUMKEYS(dst->mp_page), &key,
		    &data, NODEPGNO(srcnode), srcnode->mn_flags);
		if (rc != MDB_SUCCESS)
			return rc;
	}

	DPRINTF("dst page %lu now has %lu keys (%.1f%% filled)",
	    dst->mp_page->mp_pgno, NUMKEYS(dst->mp_page), (float)PAGEFILL(bt->md_env, dst->mp_page) / 10);

	/* Unlink the src page from parent.
	 */
	mdb_del_node(bt, src->mp_parent, src->mp_pi);
	if (src->mp_pi == 0) {
		key.mv_size = 0;
		if ((rc = mdb_update_key(bt, src->mp_parent, 0, &key)) != MDB_SUCCESS)
			return rc;
	}

	if (IS_LEAF(src->mp_page))
		bt->md_env->me_meta.mm_stat.ms_leaf_pages--;
	else
		bt->md_env->me_meta.mm_stat.ms_branch_pages--;

	mpp.mp_page = src->mp_parent;
	dh = (MDB_dhead *)src->mp_parent;
	dh--;
	mpp.mp_parent = dh->md_parent;
	mpp.mp_pi = dh->md_pi;

	return mdb_rebalance(bt, &mpp);
}

#define FILL_THRESHOLD	 250

static int
mdb_rebalance(MDB_db *db, MDB_pageparent *mpp)
{
	MDB_node	*node;
	MDB_page	*root;
	MDB_pageparent npp;
	indx_t		 si = 0, di = 0;

	assert(db != NULL);
	assert(db->md_env->me_txn != NULL);
	assert(mpp != NULL);

	DPRINTF("rebalancing %s page %lu (has %lu keys, %.1f%% full)",
	    IS_LEAF(mpp->mp_page) ? "leaf" : "branch",
	    mpp->mp_page->mp_pgno, NUMKEYS(mpp->mp_page), (float)PAGEFILL(db->md_env, mpp->mp_page) / 10);

	if (PAGEFILL(db->md_env, mpp->mp_page) >= FILL_THRESHOLD) {
		DPRINTF("no need to rebalance page %lu, above fill threshold",
		    mpp->mp_page->mp_pgno);
		return MDB_SUCCESS;
	}

	if (mpp->mp_parent == NULL) {
		if (NUMKEYS(mpp->mp_page) == 0) {
			DPRINTF("tree is completely empty");
			db->md_env->me_txn->mt_root = P_INVALID;
			db->md_env->me_meta.mm_stat.ms_depth--;
			db->md_env->me_meta.mm_stat.ms_leaf_pages--;
		} else if (IS_BRANCH(mpp->mp_page) && NUMKEYS(mpp->mp_page) == 1) {
			DPRINTF("collapsing root page!");
			db->md_env->me_txn->mt_root = NODEPGNO(NODEPTR(mpp->mp_page, 0));
			if ((root = mdbenv_get_page(db->md_env, db->md_env->me_txn->mt_root)) == NULL)
				return MDB_FAIL;
			db->md_env->me_meta.mm_stat.ms_depth--;
			db->md_env->me_meta.mm_stat.ms_branch_pages--;
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
		if ((npp.mp_page = mdbenv_get_page(db->md_env, NODEPGNO(node))) == NULL)
			return MDB_FAIL;
		npp.mp_pi = mpp->mp_pi + 1;
		si = 0;
		di = NUMKEYS(mpp->mp_page);
	} else {
		/* There is at least one neighbor to the left.
		 */
		DPRINTF("reading left neighbor");
		node = NODEPTR(mpp->mp_parent, mpp->mp_pi - 1);
		if ((npp.mp_page = mdbenv_get_page(db->md_env, NODEPGNO(node))) == NULL)
			return MDB_FAIL;
		npp.mp_pi = mpp->mp_pi - 1;
		si = NUMKEYS(npp.mp_page) - 1;
		di = 0;
	}
	npp.mp_parent = mpp->mp_parent;

	DPRINTF("found neighbor page %lu (%lu keys, %.1f%% full)",
	    npp.mp_page->mp_pgno, NUMKEYS(npp.mp_page), (float)PAGEFILL(db->md_env, npp.mp_page) / 10);

	/* If the neighbor page is above threshold and has at least two
	 * keys, move one key from it.
	 *
	 * Otherwise we should try to merge them.
	 */
	if (PAGEFILL(db->md_env, npp.mp_page) >= FILL_THRESHOLD && NUMKEYS(npp.mp_page) >= 2)
		return mdb_move_node(db, &npp, si, mpp, di);
	else { /* FIXME: if (has_enough_room()) */
		if (mpp->mp_pi == 0)
			return mdb_merge(db, &npp, mpp);
		else
			return mdb_merge(db, mpp, &npp);
	}
}

int
mdb_del(MDB_db *bt, MDB_txn *txn,
    MDB_val *key, MDB_val *data)
{
	int		 rc, exact;
	unsigned int	 ki;
	MDB_node	*leaf;
	MDB_pageparent	mpp;

	DPRINTF("========> delete key %.*s", (int)key->mv_size, (char *)key->mv_data);

	assert(key != NULL);

	if (bt == NULL || txn == NULL)
		return EINVAL;

	if (F_ISSET(txn->mt_flags, MDB_TXN_RDONLY)) {
		return EINVAL;
	}

	if (bt->md_env->me_txn != txn) {
		return EINVAL;
	}

	if (key->mv_size == 0 || key->mv_size > MAXKEYSIZE) {
		return EINVAL;
	}

	if ((rc = mdb_search_page(bt, txn, key, NULL, 1, &mpp)) != MDB_SUCCESS)
		return rc;

	leaf = mdb_search_node(bt, mpp.mp_page, key, &exact, &ki);
	if (leaf == NULL || !exact) {
		return ENOENT;
	}

	if (data && (rc = mdb_read_data(bt, NULL, leaf, data)) != MDB_SUCCESS)
		return rc;

	mdb_del_node(bt, mpp.mp_page, ki);
	bt->md_env->me_meta.mm_stat.ms_entries--;
	rc = mdb_rebalance(bt, &mpp);
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
mdb_split(MDB_db *bt, MDB_page **mpp, unsigned int *newindxp,
    MDB_val *newkey, MDB_val *newdata, pgno_t newpgno)
{
	uint8_t		 flags;
	int		 rc = MDB_SUCCESS, ins_new = 0;
	indx_t		 newindx;
	pgno_t		 pgno = 0;
	unsigned int	 i, j, split_indx;
	MDB_node	*node;
	MDB_page	*pright, *p;
	MDB_val	 sepkey, rkey, rdata;
	MDB_page	*copy;
	MDB_dpage	*mdp, *rdp, *pdp;
	MDB_dhead *dh;

	assert(bt != NULL);
	assert(bt->md_env != NULL);

	dh = ((MDB_dhead *)*mpp) - 1;
	mdp = (MDB_dpage *)dh;
	newindx = *newindxp;

	DPRINTF("-----> splitting %s page %lu and adding [%.*s] at index %i",
	    IS_LEAF(&mdp->p) ? "leaf" : "branch", mdp->p.mp_pgno,
	    (int)newkey->mv_size, (char *)newkey->mv_data, *newindxp);

	if (mdp->h.md_parent == NULL) {
		if ((pdp = mdbenv_new_page(bt->md_env, P_BRANCH, 1)) == NULL)
			return MDB_FAIL;
		mdp->h.md_pi = 0;
		mdp->h.md_parent = &pdp->p;
		bt->md_env->me_txn->mt_root = pdp->p.mp_pgno;
		DPRINTF("root split! new root = %lu", pdp->p.mp_pgno);
		bt->md_env->me_meta.mm_stat.ms_depth++;

		/* Add left (implicit) pointer. */
		if (mdb_add_node(bt, &pdp->p, 0, NULL, NULL,
		    mdp->p.mp_pgno, 0) != MDB_SUCCESS)
			return MDB_FAIL;
	} else {
		DPRINTF("parent branch page is %lu", mdp->h.md_parent->mp_pgno);
	}

	/* Create a right sibling. */
	if ((rdp = mdbenv_new_page(bt->md_env, mdp->p.mp_flags, 1)) == NULL)
		return MDB_FAIL;
	rdp->h.md_parent = mdp->h.md_parent;
	rdp->h.md_pi = mdp->h.md_pi + 1;
	DPRINTF("new right sibling: page %lu", rdp->p.mp_pgno);

	/* Move half of the keys to the right sibling. */
	if ((copy = malloc(bt->md_env->me_head.mh_psize)) == NULL)
		return MDB_FAIL;
	bcopy(&mdp->p, copy, bt->md_env->me_head.mh_psize);
	bzero(&mdp->p.mp_ptrs, bt->md_env->me_head.mh_psize - PAGEHDRSZ);
	mdp->p.mp_lower = PAGEHDRSZ;
	mdp->p.mp_upper = bt->md_env->me_head.mh_psize;

	split_indx = NUMKEYS(copy) / 2 + 1;

	/* First find the separating key between the split pages.
	 */
	bzero(&sepkey, sizeof(sepkey));
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
	if (SIZELEFT(rdp->h.md_parent) < mdb_branch_size(bt, &sepkey)) {
		rc = mdb_split(bt, &rdp->h.md_parent, &rdp->h.md_pi,
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
		rc = mdb_add_node(bt, rdp->h.md_parent, rdp->h.md_pi,
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

		rc = mdb_add_node(bt, &pdp->p, j, &rkey, &rdata, pgno,flags);
	}

	free(copy);
	return rc;
}

int
mdb_put(MDB_db *bt, MDB_txn *txn,
    MDB_val *key, MDB_val *data, unsigned int flags)
{
	int		 rc = MDB_SUCCESS, exact;
	unsigned int	 ki;
	MDB_node	*leaf;
	MDB_pageparent	mpp;

	assert(key != NULL);
	assert(data != NULL);

	if (bt == NULL || txn == NULL)
		return EINVAL;

	if (F_ISSET(txn->mt_flags, MDB_TXN_RDONLY)) {
		return EINVAL;
	}

	if (bt->md_env->me_txn != txn) {
		return EINVAL;
	}

	if (key->mv_size == 0 || key->mv_size > MAXKEYSIZE) {
		return EINVAL;
	}

	DPRINTF("==> put key %.*s, size %zu, data size %zu",
		(int)key->mv_size, (char *)key->mv_data, key->mv_size, data->mv_size);

	rc = mdb_search_page(bt, txn, key, NULL, 1, &mpp);
	if (rc == MDB_SUCCESS) {
		leaf = mdb_search_node(bt, mpp.mp_page, key, &exact, &ki);
		if (leaf && exact) {
			if (F_ISSET(flags, MDB_NOOVERWRITE)) {
				DPRINTF("duplicate key %.*s",
				    (int)key->mv_size, (char *)key->mv_data);
				return EEXIST;
			}
			mdb_del_node(bt, mpp.mp_page, ki);
		}
		if (leaf == NULL) {		/* append if not found */
			ki = NUMKEYS(mpp.mp_page);
			DPRINTF("appending key at index %i", ki);
		}
	} else if (rc == ENOENT) {
		MDB_dpage *dp;
		/* new file, just write a root leaf page */
		DPRINTF("allocating new root leaf page");
		if ((dp = mdbenv_new_page(bt->md_env, P_LEAF, 1)) == NULL) {
			return ENOMEM;
		}
		mpp.mp_page = &dp->p;
		txn->mt_root = mpp.mp_page->mp_pgno;
		bt->md_env->me_meta.mm_stat.ms_depth++;
		ki = 0;
	}
	else
		goto done;

	assert(IS_LEAF(mpp.mp_page));
	DPRINTF("there are %lu keys, should insert new key at index %i",
		NUMKEYS(mpp.mp_page), ki);

	if (SIZELEFT(mpp.mp_page) < mdb_leaf_size(bt, key, data)) {
		rc = mdb_split(bt, &mpp.mp_page, &ki, key, data, P_INVALID);
	} else {
		/* There is room already in this leaf page. */
		rc = mdb_add_node(bt, mpp.mp_page, ki, key, data, 0, 0);
	}

	if (rc != MDB_SUCCESS)
		txn->mt_flags |= MDB_TXN_ERROR;
	else
		bt->md_env->me_meta.mm_stat.ms_entries++;

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
mdbenv_stat(MDB_env *env, MDB_stat **arg)
{
	if (env == NULL || arg == NULL)
		return EINVAL;

	*arg = &env->me_meta.mm_stat;

	return MDB_SUCCESS;
}

int mdb_open(MDB_env *env, MDB_txn *txn, const char *name, unsigned int flags, MDB_db **db)
{
	if (!name) {
		*db = (MDB_db *)&env->me_db;
		return MDB_SUCCESS;
	}
	return EINVAL;
}

int mdb_stat(MDB_db *db, MDB_stat **arg)
{
	if (db == NULL || arg == NULL)
		return EINVAL;

	*arg = &db->md_stat;

	return MDB_SUCCESS;
}

void mdb_close(MDB_db *db)
{
}
