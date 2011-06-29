#ifndef _MDB_H_
#define _MDB_H_

#include <sys/types.h>

struct MDB_cursor;
struct MDB_txn;
struct MDB_db;
struct MDB_env;

typedef struct MDB_cursor MDB_cursor;
typedef struct MDB_txn MDB_txn;
typedef struct MDB_db MDB_db;
typedef struct MDB_env MDB_env;

typedef struct MDB_val {
	void		*mv_data;
	size_t		 mv_size;
} MDB_val;

typedef int  (MDB_cmp_func)(const MDB_val *a, const MDB_val *b);
typedef void (MDB_rel_func)(void *ptr, void *oldptr);

#define MDB_NOOVERWRITE	 1

typedef enum MDB_cursor_op {		/* cursor operations */
	MDB_CURSOR,				/* position at given key */
	MDB_CURSOR_EXACT,		/* position at key, or fail */
	MDB_FIRST,
	MDB_NEXT,
	MDB_LAST,				/* not implemented */
	MDB_PREV				/* not implemented */
} MDB_cursor_op;

/* return codes */
#define MDB_FAIL		-1
#define MDB_SUCCESS	 0

/* DB flags */
#define MDB_REVERSEKEY	0x02		/* use reverse string keys */
#define MDB_NOSYNC		0x10000		/* don't fsync after commit */
#define MDB_RDONLY		0x20000		/* read only */

/* environment flags */
#define MDB_FIXEDMAP	0x01		/* mmap at a fixed address */

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
int  mdbenv_stat(MDB_env *env, MDB_stat **stat);
void mdbenv_close(MDB_env *env);
int  mdbenv_get_flags(MDB_env *env, unsigned int *flags);
int  mdbenv_get_path(MDB_env *env, const char **path);
int  mdbenv_set_mapsize(MDB_env *env, size_t size);
int  mdbenv_set_maxreaders(MDB_env *env, int readers);
int  mdbenv_get_maxreaders(MDB_env *env, int *readers);
int  mdbenv_sync(MDB_env *env);
int  mdbenv_compact(MDB_env *env);

int  mdb_txn_begin(MDB_env *env, int rdonly, MDB_txn **txn);
int  mdb_txn_commit(MDB_txn *txn);
void mdb_txn_abort(MDB_txn *txn);

int  mdb_open(MDB_env *env, MDB_txn *txn, const char *name, unsigned int flags, MDB_db **db);
int  mdb_stat(MDB_db *db, MDB_stat **stat);
void mdb_close(MDB_db *db);

int  mdb_get(MDB_db *db, MDB_txn *txn, MDB_val *key, MDB_val *data);
int  mdb_put(MDB_db *db, MDB_txn *txn, MDB_val *key, MDB_val *data,
			    unsigned int flags);
int  mdb_del(MDB_db *db, MDB_txn *txn, MDB_val *key, MDB_val *data);

int  mdb_cursor_open(MDB_db *db, MDB_txn *txn, MDB_cursor **cursor);
void mdb_cursor_close(MDB_cursor *cursor);
int  mdb_cursor_get(MDB_cursor *cursor, MDB_val *key, MDB_val *data,
			    MDB_cursor_op op);

int  mdb_cmp(MDB_db *db, const MDB_val *a, const MDB_val *b);

#endif /* _MDB_H_ */
