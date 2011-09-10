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
 *	A bunch of macros to minimize the amount of platform-specific ifdefs
 *	needed throughout the rest of the code. When the features this library
 *	needs are similar enough to POSIX to be hidden in a one-or-two line
 *	replacement, this macro approach is used.
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
	/** Lock the reader mutex.
	 */
#define LOCK_MUTEX_R(env)	pthread_mutex_lock(&env->me_txns->mti_mutex)
	/** Unlock the reader mutex.
	 */
#define UNLOCK_MUTEX_R(env)	pthread_mutex_unlock(&env->me_txns->mti_mutex)

	/** Lock the writer mutex.
	 *	Only a single write transaction is allowed at a time. Other writers
	 *	will block waiting for this mutex.
	 */
#define LOCK_MUTEX_W(env)	pthread_mutex_lock(&env->me_txns->mti_wmutex)
	/** Unlock the writer mutex.
	 */
#define UNLOCK_MUTEX_W(env)	pthread_mutex_unlock(&env->me_txns->mti_wmutex)

	/** Get the error code for the last failed system function.
	 */
#define	ErrCode()	errno

	/** An abstraction for a file handle.
	 *	On POSIX systems file handles are small integers. On Windows
	 *	they're opaque pointers.
	 */
#define	HANDLE	int

	/**	A value for an invalid file handle.
	 *	Mainly used to initialize file variables and signify that they are
	 *	unused.
	 */
#define INVALID_HANDLE_VALUE	-1

	/** Get the size of a memory page for the system.
	 *	This is the basic size that the platform's memory manager uses, and is
	 *	fundamental to the use of memory-mapped files.
	 */
#define	GetPageSize(x)	(x) = sysconf(_SC_PAGE_SIZE)
#endif

/** @} */

#ifndef _WIN32
/**	A flag for opening a file and requesting synchronous data writes.
 *	This is only used when writing a meta page. It's not strictly needed;
 *	we could just do a normal write and then immediately perform a flush.
 *	But if this flag is available it saves us an extra system call.
 *
 *	@note If O_DSYNC is undefined but exists in /usr/include,
 * preferably set some compiler flag to get the definition.
 * Otherwise compile with the less efficient -DMDB_DSYNC=O_SYNC.
 */
#ifndef MDB_DSYNC
# define MDB_DSYNC	O_DSYNC
#endif
#endif

	/** A page number in the database.
	 *	Note that 64 bit page numbers are overkill, since pages themselves
	 *	already represent 12-13 bits of addressable memory, and the OS will
	 *	always limit applications to a maximum of 63 bits of address space.
	 *
	 *	@note In the #MDB_node structure, we only store 48 bits of this value,
	 *	which thus limits us to only 60 bits of addressable data.
	 */
typedef ULONG		pgno_t;

/** @defgroup debug	Debug Macros
 *	@{
 */
#ifndef DEBUG
	/**	Enable debug output.
	 *	Set this to 1 for copious tracing. Set to 2 to add dumps of all IDLs
	 *	read from and written to the database (used for free space management).
	 */
#define DEBUG 0
#endif

#if !(__STDC_VERSION__ >= 199901L || defined(__GNUC__))
# define DPRINTF	(void)	/* Vararg macros may be unsupported */
#elif DEBUG
	/**	Print a debug message with printf formatting. */
# define DPRINTF(fmt, ...)	/**< Requires 2 or more args */ \
	fprintf(stderr, "%s:%d:(%p) " fmt "\n", __func__, __LINE__, pthread_self(), __VA_ARGS__)
#else
# define DPRINTF(fmt, ...)	((void) 0)
#endif
	/**	Print a debug string.
	 *	The string is printed literally, with no format processing.
	 */
#define DPUTS(arg)	DPRINTF("%s", arg)
/** @} */

	/** A default memory page size.
	 *	The actual size is platform-dependent, but we use this for
	 *	boot-strapping. We probably should not be using this any more.
	 *	The #GetPageSize() macro is used to get the actual size.
	 *
	 *	Note that we don't currently support Huge pages. On Linux,
	 *	regular data files cannot use Huge pages, and in general
	 *	Huge pages aren't actually pageable. We rely on the OS
	 *	demand-pager to read our data and page it out when memory
	 *	pressure from other processes is high. So until OSs have
	 *	actual paging support for Huge pages, they're not viable.
	 */
#define PAGESIZE	 4096

	/** The minimum number of keys required in a database page.
	 *	Setting this to a larger value will place a smaller bound on the
	 *	maximum size of a data item. Data items larger than this size will
	 *	be pushed into overflow pages instead of being stored directly in
	 *	the B-tree node. This value used to default to 4. With a page size
	 *	of 4096 bytes that meant that any item larger than 1024 bytes would
	 *	go into an overflow page. That also meant that on average 2-3KB of
	 *	each overflow page was wasted space. The value cannot be lower than
	 *	2 because then there would no longer be a tree structure. With this
	 *	value, items larger than 2KB will go into overflow pages, and on
	 *	average only 1KB will be wasted.
	 */
#define MDB_MINKEYS	 2

	/**	A stamp that identifies a file as an MDB file.
	 *	There's nothing special about this value other than that it is easily
	 *	recognizable, and it will reflect any byte order mismatches.
	 */
#define MDB_MAGIC	 0xBEEFC0DE

	/**	The version number for a database's file format. */
#define MDB_VERSION	 1

	/**	The maximum size of a key in the database.
	 *	While data items have essentially unbounded size, we require that
	 *	keys all fit onto a regular page. This limit could be raised a bit
	 *	further if needed; to something just under #PAGESIZE / #MDB_MINKEYS.
	 */
#define MAXKEYSIZE	 511

#if DEBUG
	/**	A key buffer.
	 *	@ingroup debug
	 *	This is used for printing a hex dump of a key's contents.
	 */
#define DKBUF	char kbuf[(MAXKEYSIZE*2+1)]
	/**	Display a key in hex.
	 *	@ingroup debug
	 *	Invoke a function to display a key in hex.
	 */
#define	DKEY(x)	mdb_dkey(x, kbuf)
#else
#define	DKBUF
#define DKEY(x)
#endif

/**	@defgroup lazylock	Lazy Locking
 *	Macros for locks that are't actually needed.
 *	The DB view is always consistent because all writes are wrapped in
 *	the wmutex. Finer-grained locks aren't necessary.
 *	@{
 */
#ifndef	LAZY_LOCKS
	/**	Use lazy locking. I.e., don't lock these accesses at all. */
#define	LAZY_LOCKS	1
#endif
#if	LAZY_LOCKS
	/** Grab the reader lock */
#define	LAZY_MUTEX_LOCK(x)
	/** Release the reader lock */
#define	LAZY_MUTEX_UNLOCK(x)
	/** Release the DB table reader/writer lock */
#define	LAZY_RWLOCK_UNLOCK(x)
	/** Grab the DB table write lock */
#define	LAZY_RWLOCK_WRLOCK(x)
	/** Grab the DB table read lock */
#define	LAZY_RWLOCK_RDLOCK(x)
	/** Declare the DB table rwlock */
#define	LAZY_RWLOCK_DEF(x)
	/** Initialize the DB table rwlock */
#define	LAZY_RWLOCK_INIT(x,y)
	/**	Destroy the DB table rwlock */
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
/** @} */

	/** An invalid page number.
	 *	Mainly used to denote an empty tree.
	 */
#define P_INVALID	 (~0UL)

	/** Test if a flag \b f is set in a flag word \b w. */
#define F_ISSET(w, f)	 (((w) & (f)) == (f))

	/**	Used for offsets within a single page.
	 *	Since memory pages are typically 4 or 8KB in size, 12-13 bits,
	 *	this is plenty.
	 */
typedef uint16_t	 indx_t;

	/**	Default size of memory map.
	 *	This is certainly too small for any actual applications. Apps should always set
	 *	the size explicitly using #mdb_env_set_mapsize().
	 */
#define DEFAULT_MAPSIZE	1048576

/**	@defgroup readers	Reader Lock Table
 *	Readers don't acquire any locks for their data access. Instead, they
 *	simply record their transaction ID in the reader table. The reader
 *	mutex is needed just to find an empty slot in the reader table. The
 *	slot's address is saved in thread-specific data so that subsequent read
 *	transactions started by the same thread need no further locking to proceed.
 *
 *	Since the database uses multi-version concurrency control, readers don't
 *	actually need any locking. This table is used to keep track of which
 *	readers are using data from which old transactions, so that we'll know
 *	when a particular old transaction is no longer in use. Old transactions
 *	that have discarded any data pages can then have those pages reclaimed
 *	for use by a later write transaction.
 *
 *	The lock table is constructed such that reader slots are aligned with the
 *	processor's cache line size. Any slot is only ever used by one thread.
 *	This alignment guarantees that there will be no contention or cache
 *	thrashing as threads update their own slot info, and also eliminates
 *	any need for locking when accessing a slot.
 *
 *	A writer thread will scan every slot in the table to determine the oldest
 *	outstanding reader transaction. Any freed pages older than this will be
 *	reclaimed by the writer. The writer doesn't use any locks when scanning
 *	this table. This means that there's no guarantee that the writer will
 *	see the most up-to-date reader info, but that's not required for correct
 *	operation - all we need is to know the upper bound on the oldest reader,
 *	we don't care at all about the newest reader. So the only consequence of
 *	reading stale information here is that old pages might hang around a
 *	while longer before being reclaimed. That's actually good anyway, because
 *	the longer we delay reclaiming old pages, the more likely it is that a
 *	string of contiguous pages can be found after coalescing old pages from
 *	many old transactions together.
 *
 *	@todo We don't actually do such coalescing yet, we grab pages from one
 *	old transaction at a time.
 *	@{
 */
	/**	Number of slots in the reader table.
	 *	This value was chosen somewhat arbitrarily. 126 readers plus a
	 *	couple mutexes fit exactly into 8KB on my development machine.
	 *	Applications should set the table size using #mdb_env_set_maxreaders().
	 */
#define DEFAULT_READERS	126

	/**	The size of a CPU cache line in bytes. We want our lock structures
	 *	aligned to this size to avoid false cache line sharing in the
	 *	lock table.
	 *	This value works for most CPUs. For Itanium this should be 128.
	 */
#ifndef CACHELINE
#define CACHELINE	64
#endif

	/**	The information we store in a single slot of the reader table.
	 *	In addition to a transaction ID, we also record the process and
	 *	thread ID that owns a slot, so that we can detect stale information,
	 *	e.g. threads or processes that went away without cleaning up.
	 *	@note We currently don't check for stale records. We simply re-init
	 *	the table when we know that we're the only process opening the
	 *	lock file.
	 */
typedef struct MDB_rxbody {
	/**	The current Transaction ID when this transaction began.
	 *	Multiple readers that start at the same time will probably have the
	 *	same ID here. Again, it's not important to exclude them from
	 *	anything; all we need to know is which version of the DB they
	 *	started from so we can avoid overwriting any data used in that
	 *	particular version.
	 */
	ULONG		mrb_txnid;
	/** The process ID of the process owning this reader txn. */
	pid_t		mrb_pid;
	/** The thread ID of the thread owning this txn. */
	pthread_t	mrb_tid;
} MDB_rxbody;

	/** The actual reader record, with cacheline padding. */
typedef struct MDB_reader {
	union {
		MDB_rxbody mrx;
		/** shorthand for mrb_txnid */
#define	mr_txnid	mru.mrx.mrb_txnid
#define	mr_pid	mru.mrx.mrb_pid
#define	mr_tid	mru.mrx.mrb_tid
		/** cache line alignment */
		char pad[(sizeof(MDB_rxbody)+CACHELINE-1) & ~(CACHELINE-1)];
	} mru;
} MDB_reader;

	/** The header for the reader table.
	 *	The table resides in a memory-mapped file. (This is a different file
	 *	than is used for the main database.)
	 *
	 *	For POSIX the actual mutexes reside in the shared memory of this
	 *	mapped file. On Windows, mutexes are named objects allocated by the
	 *	kernel; we store the mutex names in this mapped file so that other
	 *	processes can grab them. This same approach will also be used on
	 *	MacOSX/Darwin (using named semaphores) since MacOSX doesn't support
	 *	process-shared POSIX mutexes.
	 */
typedef struct MDB_txbody {
		/** Stamp identifying this as an MDB lock file. It must be set
		 *	to #MDB_MAGIC. */
	uint32_t	mtb_magic;
		/** Version number of this lock file. Must be set to #MDB_VERSION. */
	uint32_t	mtb_version;
#ifdef _WIN32
	char	mtb_rmname[32];
#else
		/** Mutex protecting access to this table.
		 *	This is the reader lock that #LOCK_MUTEX_R acquires.
		 */
	pthread_mutex_t	mtb_mutex;
#endif
		/**	The ID of the last transaction committed to the database.
		 *	This is recorded here only for convenience; the value can always
		 *	be determined by reading the main database meta pages.
		 */
	ULONG		mtb_txnid;
		/** The number of slots that have been used in the reader table.
		 *	This always records the maximum count, it is not decremented
		 *	when readers release their slots.
		 */
	uint32_t	mtb_numreaders;
		/**	The ID of the most recent meta page in the database.
		 *	This is recorded here only for convenience; the value can always
		 *	be determined by reading the main database meta pages.
		 */
	uint32_t	mtb_me_toggle;
} MDB_txbody;

	/** The actual reader table definition. */
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
/** @} */

/** Common header for all page types.
 * Overflow pages occupy a number of contiguous pages with no
 * headers on any page after the first.
 */
typedef struct MDB_page {
#define	mp_pgno	mp_p.p_pgno
#define	mp_next	mp_p.p_next
	union padded {
		pgno_t		p_pgno;	/**< page number */
		void *		p_next;	/**< for in-memory list of freed structs */
	} mp_p;
#define	P_BRANCH	 0x01		/**< branch page */
#define	P_LEAF		 0x02		/**< leaf page */
#define	P_OVERFLOW	 0x04		/**< overflow page */
#define	P_META		 0x08		/**< meta page */
#define	P_DIRTY		 0x10		/**< dirty page */
#define	P_LEAF2		 0x20		/**< for #MDB_DUPFIXED records */
	uint32_t	mp_flags;
#define mp_lower	mp_pb.pb.pb_lower
#define mp_upper	mp_pb.pb.pb_upper
#define mp_pages	mp_pb.pb_pages
	union page_bounds {
		struct {
			indx_t		pb_lower;		/**< lower bound of free space */
			indx_t		pb_upper;		/**< upper bound of free space */
		} pb;
		uint32_t	pb_pages;	/**< number of overflow pages */
	} mp_pb;
	indx_t		mp_ptrs[1];		/**< dynamic size */
} MDB_page;

	/** Size of the page header, excluding dynamic data at the end */
#define PAGEHDRSZ	 ((unsigned) offsetof(MDB_page, mp_ptrs))

	/** Address of first usable data byte in a page, after the header */
#define METADATA(p)	 ((void *)((char *)(p) + PAGEHDRSZ))

	/** Number of nodes on a page */
#define NUMKEYS(p)	 (((p)->mp_lower - PAGEHDRSZ) >> 1)

	/** The amount of space remaining in the page */
#define SIZELEFT(p)	 (indx_t)((p)->mp_upper - (p)->mp_lower)

	/** The percentage of space used in the page, in tenths of a percent. */
#define PAGEFILL(env, p) (1000L * ((env)->me_psize - PAGEHDRSZ - SIZELEFT(p)) / \
				((env)->me_psize - PAGEHDRSZ))
	/** The minimum page fill factor, in tenths of a percent.
	 *	Pages emptier than this are candidates for merging.
	 */
#define FILL_THRESHOLD	 250

	/** Test if a page is a leaf page */
#define IS_LEAF(p)	 F_ISSET((p)->mp_flags, P_LEAF)
	/** Test if a page is a LEAF2 page */
#define IS_LEAF2(p)	 F_ISSET((p)->mp_flags, P_LEAF2)
	/** Test if a page is a branch page */
#define IS_BRANCH(p)	 F_ISSET((p)->mp_flags, P_BRANCH)
	/** Test if a page is an overflow page */
#define IS_OVERFLOW(p)	 F_ISSET((p)->mp_flags, P_OVERFLOW)

	/** The number of overflow pages needed to store the given size. */
#define OVPAGES(size, psize)	((PAGEHDRSZ-1 + (size)) / (psize) + 1)

	/** Header for a single key/data pair within a page.
	 * We guarantee 2-byte alignment for nodes.
	 */
typedef struct MDB_node {
	/** lo and hi are used for data size on leaf nodes and for
	 * child pgno on branch nodes. On 64 bit platforms, flags
	 * is also used for pgno. (branch nodes ignore flags)
	 */
	unsigned short	mn_lo;
	unsigned short	mn_hi;			/**< part of dsize or pgno */
	unsigned short	mn_flags;		/**< flags for special node types */
#define F_BIGDATA	 0x01			/**< data put on overflow page */
#define F_SUBDATA	 0x02			/**< data is a sub-database */
#define F_DUPDATA	 0x04			/**< data has duplicates */
	unsigned short	mn_ksize;		/**< key size */
	char		mn_data[1];			/**< key and data are appended here */
} MDB_node;

	/** Size of the node header, excluding dynamic data at the end */
#define NODESIZE	 offsetof(MDB_node, mn_data)

	/** Size of a node in a branch page with a given key.
	 *	This is just the node header plus the key, there is no data.
	 */
#define INDXSIZE(k)	 (NODESIZE + ((k) == NULL ? 0 : (k)->mv_size))

	/** Size of a node in a leaf page with a given key and data.
	 *	This is node header plus key plus data size.
	 */
#define LEAFSIZE(k, d)	 (NODESIZE + (k)->mv_size + (d)->mv_size)

	/** Address of node \b i in page \b p */
#define NODEPTR(p, i)	 ((MDB_node *)((char *)(p) + (p)->mp_ptrs[i]))

	/** Address of the key for the node */
#define NODEKEY(node)	 (void *)((node)->mn_data)

	/** Address of the data for a node */
#define NODEDATA(node)	 (void *)((char *)(node)->mn_data + (node)->mn_ksize)

	/** Get the page number pointed to by a branch node */
#if LONG_MAX == 0x7fffffff
#define NODEPGNO(node)	 ((node)->mn_lo | ((node)->mn_hi << 16))
	/** Set the page number in a branch node */
#define SETPGNO(node,pgno)	do { \
	(node)->mn_lo = (pgno) & 0xffff; (node)->mn_hi = (pgno) >> 16;} while(0)
#else
#define NODEPGNO(node)	 ((node)->mn_lo | ((node)->mn_hi << 16) | ((unsigned long)(node)->mn_flags << 32))
	/** Set the page number in a branch node */
#define SETPGNO(node,pgno)	do { \
	(node)->mn_lo = (pgno) & 0xffff; (node)->mn_hi = (pgno) >> 16; \
	(node)->mn_flags = (pgno) >> 32; } while(0)
#endif

	/** Get the size of the data in a leaf node */
#define NODEDSZ(node)	 ((node)->mn_lo | ((unsigned)(node)->mn_hi << 16))
	/** Set the size of the data for a leaf node */
#define SETDSZ(node,size)	do { \
	(node)->mn_lo = (size) & 0xffff; (node)->mn_hi = (size) >> 16;} while(0)
	/** The size of a key in a node */
#define NODEKSZ(node)	 ((node)->mn_ksize)

	/** The address of a key in a LEAF2 page.
	 *	LEAF2 pages are used for #MDB_DUPFIXED sorted-duplicate sub-DBs.
	 *	There are no node headers, keys are stored contiguously.
	 */
#define LEAF2KEY(p, i, ks)	((char *)(p) + PAGEHDRSZ + ((i)*(ks)))

	/** Set the \b node's key into \b key, if requested. */
#define MDB_SET_KEY(node, key)	if (key!=NULL) {(key)->mv_size = NODEKSZ(node); (key)->mv_data = NODEKEY(node);}

	/** Information about a single database in the environment. */
typedef struct MDB_db {
	uint32_t	md_pad;		/**< also ksize for LEAF2 pages */
	uint16_t	md_flags;	/**< @ref mdb_open */
	uint16_t	md_depth;	/**< depth of this tree */
	ULONG		md_branch_pages;	/**< number of internal pages */
	ULONG		md_leaf_pages;		/**< number of leaf pages */
	ULONG		md_overflow_pages;	/**< number of overflow pages */
	ULONG		md_entries;		/**< number of data items */
	pgno_t		md_root;		/**< the root page of this tree */
} MDB_db;

	/** Handle for the DB used to track free pages. */
#define	FREE_DBI	0
	/** Handle for the default DB. */
#define	MAIN_DBI	1

	/** Meta page content. */
typedef struct MDB_meta {
		/** Stamp identifying this as an MDB data file. It must be set
		 *	to #MDB_MAGIC. */
	uint32_t	mm_magic;
		/** Version number of this lock file. Must be set to #MDB_VERSION. */
	uint32_t	mm_version;
	void		*mm_address;		/**< address for fixed mapping */
	size_t		mm_mapsize;			/**< size of mmap region */
	MDB_db		mm_dbs[2];			/**< first is free space, 2nd is main db */
	/** The size of pages used in this DB */
#define	mm_psize	mm_dbs[0].md_pad
	/** Any persistent environment flags. @ref mdb_env */
#define	mm_flags	mm_dbs[0].md_flags
	pgno_t		mm_last_pg;			/**< last used page in file */
	ULONG		mm_txnid;			/**< txnid that committed this page */
} MDB_meta;

	/** Auxiliary DB info.
	 *	The information here is mostly static/read-only. There is
	 *	only a single copy of this record in the environment.
	 *	The \b md_dirty flag is not read-only, but only a write
	 *	transaction can ever update it, and only write transactions
	 *	need to worry about it.
	 */
typedef struct MDB_dbx {
	MDB_val		md_name;		/**< name of the database */
	MDB_cmp_func	*md_cmp;	/**< function for comparing keys */
	MDB_cmp_func	*md_dcmp;	/**< function for comparing data items */
	MDB_rel_func	*md_rel;	/**< user relocate function */
	MDB_dbi	md_parent;			/**< parent DB of a sub-DB */
	unsigned int	md_dirty;	/**< TRUE if DB was written in this txn */
} MDB_dbx;

	/** A database transaction.
	 *	Every operation requires a transaction handle.
	 */
struct MDB_txn {
	pgno_t		mt_next_pgno;	/**< next unallocated page */
	/** The ID of this transaction. IDs are integers incrementing from 1.
	 *	Only committed write transactions increment the ID. If a transaction
	 *	aborts, the ID may be re-used by the next writer.
	 */
	ULONG		mt_txnid;
	MDB_env		*mt_env;		/**< the DB environment */
	/** The list of pages that became unused during this transaction.
	 *	This is an #IDL.
	 */
	pgno_t		*mt_free_pgs;
	union {
		ID2L	dirty_list;	/**< modified pages */
		MDB_reader	*reader;	/**< this thread's slot in the reader table */
	} mt_u;
	/** Array of records for each DB known in the environment. */
	MDB_dbx		*mt_dbxs;
	/** Array of MDB_db records for each known DB */
	MDB_db		*mt_dbs;
	/**	Number of DB records in use. This number only ever increments;
	 *	we don't decrement it when individual DB handles are closed.
	 */
	unsigned int	mt_numdbs;

#define MDB_TXN_RDONLY		0x01		/**< read-only transaction */
#define MDB_TXN_ERROR		0x02		/**< an error has occurred */
	unsigned int	mt_flags;
	/** Tracks which of the two meta pages was used at the start
	 * 	of this transaction.
	 */
	unsigned int	mt_toggle;
};

/** Enough space for 2^32 nodes with minimum of 2 keys per node. I.e., plenty.
 * At 4 keys per node, enough for 2^64 nodes, so there's probably no need to
 * raise this on a 64 bit machine.
 */
#define CURSOR_STACK		 32

struct MDB_xcursor;

	/** Cursors are used for all DB operations */
struct MDB_cursor {
	/** Context used for databases with #MDB_DUPSORT, otherwise NULL */
	struct MDB_xcursor	*mc_xcursor;
	/** The transaction that owns this cursor */
	MDB_txn		*mc_txn;
	/** The database handle this cursor operates on */
	MDB_dbi		mc_dbi;
	unsigned short 	mc_snum;	/**< number of pushed pages */
	unsigned short	mc_top;		/**< index of top page, mc_snum-1 */
	unsigned int	mc_flags;
#define C_INITIALIZED	0x01	/**< cursor has been initialized and is valid */
#define C_EOF	0x02			/**< No more data */
#define C_XDIRTY	0x04		/**< @deprecated mc_xcursor needs to be flushed */
	MDB_page	*mc_pg[CURSOR_STACK];	/**< stack of pushed pages */
	indx_t		mc_ki[CURSOR_STACK];	/**< stack of page indices */
};

	/** Context for sorted-dup records.
	 *	We could have gone to a fully recursive design, with arbitrarily
	 *	deep nesting of sub-databases. But for now we only handle these
	 *	levels - main DB, optional sub-DB, sorted-duplicate DB.
	 */
typedef struct MDB_xcursor {
	/** A sub-cursor for traversing the Dup DB */
	MDB_cursor mx_cursor;
	/** A fake transaction struct for pointing to our own table
	 *	of DB info.
	 */
	MDB_txn mx_txn;
	/**	Our private DB information tables. Slots 0 and 1 are always
	 *	copies of the corresponding slots in the main transaction. These
	 *	hold the FREEDB and MAINDB, respectively. If the main cursor is
	 *	on a sub-database, that will be copied to slot 2, and the duplicate
	 *	database info will be in slot 3. If the main cursor is on the MAINDB
	 *	then the duplicate DB info will be in slot 2 and slot 3 will be unused.
	 */
	MDB_dbx	mx_dbxs[4];
	/** MDB_db table */
	MDB_db	mx_dbs[4];
} MDB_xcursor;

	/** A set of pages freed by an earlier transaction. */
typedef struct MDB_oldpages {
	/** Usually we only read one record from the FREEDB at a time, but
	 *	in case we read more, this will chain them together.
	 */
	struct MDB_oldpages *mo_next;
	/**	The ID of the transaction in which these pages were freed. */
	ULONG		mo_txnid;
	/** An #IDL of the pages */
	pgno_t		mo_pages[1];	/* dynamic */
} MDB_oldpages;

	/** The database environment. */
struct MDB_env {
	HANDLE		me_fd;		/**< The main data file */
	HANDLE		me_lfd;		/**< The lock file */
	HANDLE		me_mfd;			/**< just for writing the meta pages */
	/** Failed to update the meta page. Probably an I/O error. */
#define	MDB_FATAL_ERROR	0x80000000U
	uint32_t 	me_flags;
	uint32_t	me_extrapad;	/**< unused for now */
	unsigned int	me_maxreaders;	/**< size of the reader table */
	unsigned int	me_numdbs;		/**< number of DBs opened */
	unsigned int	me_maxdbs;		/**< size of the DB table */
	char		*me_path;		/**< path to the DB files */
	char		*me_map;		/**< the memory map of the data file */
	MDB_txninfo	*me_txns;		/**< the memory map of the lock file */
	MDB_meta	*me_metas[2];	/**< pointers to the two meta pages */
	MDB_txn		*me_txn;		/**< current write transaction */
	size_t		me_mapsize;		/**< size of the data memory map */
	off_t		me_size;		/**< current file size */
	pgno_t		me_maxpg;		/**< me_mapsize / me_psize */
	unsigned int	me_psize;	/**< size of a page, from #GetPageSize */
	unsigned int	me_db_toggle;	/**< which DB table is current */
	MDB_dbx		*me_dbxs;		/**< array of static DB info */
	MDB_db		*me_dbs[2];		/**< two arrays of MDB_db info */
	MDB_oldpages *me_pghead;	/**< list of old page records */
	pthread_key_t	me_txkey;	/**< thread-key for readers */
	MDB_page	*me_dpages;		/**< list of malloc'd blocks for re-use */
	/** IDL of pages that became unused in a write txn */
	pgno_t		me_free_pgs[MDB_IDL_UM_SIZE];
	/** ID2L of pages that were written during a write txn */
	ID2			me_dirty_list[MDB_IDL_UM_SIZE];
	/** rwlock for the DB tables, if #LAZY_LOCKS is false */
	LAZY_RWLOCK_DEF(me_dblock);
#ifdef _WIN32
	HANDLE		me_rmutex;		/* Windows mutexes don't reside in shared mem */
	HANDLE		me_wmutex;
#endif
};
	/** max number of pages to commit in one writev() call */
#define MDB_COMMIT_PAGES	 64

static MDB_page *mdb_alloc_page(MDB_cursor *mc, int num);
static int 		mdb_touch(MDB_cursor *mc);

static int  mdb_search_page_root(MDB_cursor *mc,
			    MDB_val *key, int modify);
static int  mdb_search_page(MDB_cursor *mc,
			    MDB_val *key, int modify);

static int  mdb_env_read_header(MDB_env *env, MDB_meta *meta);
static int  mdb_env_read_meta(MDB_env *env, int *which);
static int  mdb_env_write_meta(MDB_txn *txn);
static int  mdb_get_page(MDB_txn *txn, pgno_t pgno, MDB_page **mp);

static MDB_node *mdb_search_node(MDB_cursor *mc, MDB_val *key, int *exactp);
static int  mdb_add_node(MDB_cursor *mc, indx_t indx,
			    MDB_val *key, MDB_val *data, pgno_t pgno, uint8_t flags);
static void mdb_del_node(MDB_page *mp, indx_t indx, int ksize);
static int mdb_del0(MDB_cursor *mc, MDB_node *leaf);
static int  mdb_read_data(MDB_txn *txn, MDB_node *leaf, MDB_val *data);

static int	mdb_rebalance(MDB_cursor *mc);
static int	mdb_update_key(MDB_page *mp, indx_t indx, MDB_val *key);
static int	mdb_move_node(MDB_cursor *csrc, MDB_cursor *cdst);
static int	mdb_merge(MDB_cursor *csrc, MDB_cursor *cdst);
static int	mdb_split(MDB_cursor *mc, MDB_val *newkey, MDB_val *newdata,
				pgno_t newpgno);
static MDB_page *mdb_new_page(MDB_cursor *mc, uint32_t flags, int num);

static void	cursor_pop_page(MDB_cursor *mc);
static int	cursor_push_page(MDB_cursor *mc, MDB_page *mp);

static int	mdb_sibling(MDB_cursor *mc, int move_right);
static int	mdb_cursor_next(MDB_cursor *mc, MDB_val *key, MDB_val *data, MDB_cursor_op op);
static int	mdb_cursor_prev(MDB_cursor *mc, MDB_val *key, MDB_val *data, MDB_cursor_op op);
static int	mdb_cursor_set(MDB_cursor *mc, MDB_val *key, MDB_val *data, MDB_cursor_op op,
				int *exactp);
static int	mdb_cursor_first(MDB_cursor *mc, MDB_val *key, MDB_val *data);
static int	mdb_cursor_last(MDB_cursor *mc, MDB_val *key, MDB_val *data);

static void	mdb_xcursor_init0(MDB_cursor *mc);
static void	mdb_xcursor_init1(MDB_cursor *mc, MDB_node *node);
static void	mdb_xcursor_init2(MDB_cursor *mc);
static void	mdb_xcursor_fini(MDB_cursor *mc);

static size_t	mdb_leaf_size(MDB_env *env, MDB_val *key, MDB_val *data);
static size_t	mdb_branch_size(MDB_env *env, MDB_val *key);

static void mdb_default_cmp(MDB_txn *txn, MDB_dbi dbi);

/** @cond */
static MDB_cmp_func	memncmp, memnrcmp, intcmp, cintcmp;
/** @endcond */

#ifdef _WIN32
static SECURITY_DESCRIPTOR mdb_null_sd;
static SECURITY_ATTRIBUTES mdb_all_sa;
static int mdb_sec_inited;
#endif

/** Return the library version info. */
char *
mdb_version(int *major, int *minor, int *patch)
{
	if (major) *major = MDB_VERSION_MAJOR;
	if (minor) *minor = MDB_VERSION_MINOR;
	if (patch) *patch = MDB_VERSION_PATCH;
	return MDB_VERSION_STRING;
}

/** Table of descriptions for MDB @ref errors */
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
/** Display a key in hexadecimal and return the address of the result.
 * @param[in] key the key to display
 * @param[in] buf the buffer to write into. Should always be #DKBUF.
 * @return The key in hexadecimal form.
 */
char *
mdb_dkey(MDB_val *key, char *buf)
{
	char *ptr = buf;
	unsigned char *c = key->mv_data;
	unsigned int i;
	if (key->mv_size > MAXKEYSIZE)
		return "MAXKEYSIZE";
	/* may want to make this a dynamic check: if the key is mostly
	 * printable characters, print it as-is instead of converting to hex.
	 */
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

/** Compare two data items according to a particular database.
 * This returns a comparison as if the two items were data items of
 * a sorted duplicates #MDB_DUPSORT database.
 * @param[in] txn A transaction handle returned by #mdb_txn_begin()
 * @param[in] dbi A database handle returned by #mdb_open()
 * @param[in] a The first item to compare
 * @param[in] b The second item to compare
 * @return < 0 if a < b, 0 if a == b, > 0 if a > b
 */
int
mdb_dcmp(MDB_txn *txn, MDB_dbi dbi, const MDB_val *a, const MDB_val *b)
{
	if (txn->mt_dbxs[dbi].md_dcmp)
		return txn->mt_dbxs[dbi].md_dcmp(a, b);
	else
		return EINVAL;	/* too bad you can't distinguish this from a valid result */
}

/** Allocate pages for writing.
 * If there are free pages available from older transactions, they
 * will be re-used first. Otherwise a new page will be allocated.
 * @param[in] mc cursor A cursor handle identifying the transaction and
 *	database for which we are allocating.
 * @param[in] num the number of pages to allocate.
 * @return Address of the allocated page(s). Requests for multiple pages
 *  will always be satisfied by a single contiguous chunk of memory.
 */
static MDB_page *
mdb_alloc_page(MDB_cursor *mc, int num)
{
	MDB_txn *txn = mc->mc_txn;
	MDB_page *np;
	pgno_t pgno = P_INVALID;
	ID2 mid;

	if (txn->mt_txnid > 2) {

		if (!txn->mt_env->me_pghead && mc->mc_dbi != FREE_DBI &&
			txn->mt_dbs[FREE_DBI].md_root != P_INVALID) {
			/* See if there's anything in the free DB */
			MDB_cursor m2;
			MDB_node *leaf;
			ULONG *kptr, oldest;

			m2.mc_txn = txn;
			m2.mc_dbi = FREE_DBI;
			m2.mc_snum = 0;
			m2.mc_flags = 0;
			mdb_search_page(&m2, NULL, 0);
			leaf = NODEPTR(m2.mc_pg[m2.mc_top], 0);
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
				m2.mc_ki[m2.mc_top] = 0;
				m2.mc_flags = C_INITIALIZED;
				mdb_cursor_del(&m2, 0);
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
		np = txn->mt_env->me_dpages;
		txn->mt_env->me_dpages = np->mp_next;
	} else {
		if ((np = malloc(txn->mt_env->me_psize * num )) == NULL)
			return NULL;
	}
	if (pgno == P_INVALID) {
		np->mp_pgno = txn->mt_next_pgno;
		txn->mt_next_pgno += num;
	} else {
		np->mp_pgno = pgno;
	}
	mid.mid = np->mp_pgno;
	mid.mptr = np;
	mdb_mid2l_insert(txn->mt_u.dirty_list, &mid);

	return np;
}

/** Touch a page: make it dirty and re-insert into tree with updated pgno.
 * @param[in] mc cursor pointing to the page to be touched
 * @return 0 on success, non-zero on failure.
 */
static int
mdb_touch(MDB_cursor *mc)
{
	MDB_page *mp = mc->mc_pg[mc->mc_top];
	pgno_t	pgno;

	if (!F_ISSET(mp->mp_flags, P_DIRTY)) {
		MDB_page *np;
		if ((np = mdb_alloc_page(mc, 1)) == NULL)
			return ENOMEM;
		DPRINTF("touched db %u page %lu -> %lu", mc->mc_dbi, mp->mp_pgno, np->mp_pgno);
		assert(mp->mp_pgno != np->mp_pgno);
		mdb_midl_append(mc->mc_txn->mt_free_pgs, mp->mp_pgno);
		pgno = np->mp_pgno;
		memcpy(np, mp, mc->mc_txn->mt_env->me_psize);
		mp = np;
		mp->mp_pgno = pgno;
		mp->mp_flags |= P_DIRTY;

		mc->mc_pg[mc->mc_top] = mp;
		/** If this page has a parent, update the parent to point to
		 * this new page.
		 */
		if (mc->mc_top)
			SETPGNO(NODEPTR(mc->mc_pg[mc->mc_top-1], mc->mc_ki[mc->mc_top-1]), mp->mp_pgno);
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

/** Common code for #mdb_txn_begin() and #mdb_txn_renew().
 * @param[in] txn the transaction handle to initialize
 * @return 0 on success, non-zero on failure. This can only
 * fail for read-only transactions, and then only if the
 * reader table is full.
 */
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

/** Common code for #mdb_txn_reset() and #mdb_txn_abort().
 * @param[in] txn the transaction handle to reset
 */
static inline void
mdb_txn_reset0(MDB_txn *txn)
{
	MDB_env	*env = txn->mt_env;

	if (F_ISSET(txn->mt_flags, MDB_TXN_RDONLY)) {
		txn->mt_u.reader->mr_txnid = 0;
	} else {
		MDB_oldpages *mop;
		MDB_page *dp;
		unsigned int i;

		/* return all dirty pages to dpage list */
		for (i=1; i<=txn->mt_u.dirty_list[0].mid; i++) {
			dp = txn->mt_u.dirty_list[i].mptr;
			if (!IS_OVERFLOW(dp) || dp->mp_pages == 1) {
				dp->mp_next = txn->mt_env->me_dpages;
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
		/* The writer mutex was locked in mdb_txn_begin. */
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
	MDB_page	*dp;
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
		/* make sure first page of freeDB is touched and on freelist */
		mdb_search_page(&mc, NULL, 1);
	}
	/* save to free list */
	if (!MDB_IDL_IS_ZERO(txn->mt_free_pgs)) {
		MDB_val key, data;
		ULONG i;

		/* make sure last page of freeDB is touched and on freelist */
		key.mv_size = MAXKEYSIZE+1;
		key.mv_data = NULL;
		mdb_search_page(&mc, &key, 1);

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
			size_t wsize;
			dp = txn->mt_u.dirty_list[i].mptr;
			DPRINTF("committing page %lu", dp->mp_pgno);
			size = dp->mp_pgno * env->me_psize;
			ov.Offset = size & 0xffffffff;
			ov.OffsetHigh = size >> 16;
			ov.OffsetHigh >>= 16;
			/* clear dirty flag */
			dp->mp_flags &= ~P_DIRTY;
			wsize = env->me_psize;
			if (IS_OVERFLOW(dp)) wsize *= dp->mp_pages;
			rc = WriteFile(env->me_fd, dp, wsize, NULL, &ov);
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
			if (dp->mp_pgno != next) {
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
				lseek(env->me_fd, dp->mp_pgno * env->me_psize, SEEK_SET);
				next = dp->mp_pgno;
			}
			DPRINTF("committing page %lu", dp->mp_pgno);
			iov[n].iov_len = env->me_psize;
			if (IS_OVERFLOW(dp)) iov[n].iov_len *= dp->mp_pages;
			iov[n].iov_base = dp;
			size += iov[n].iov_len;
			next = dp->mp_pgno + (IS_OVERFLOW(dp) ? dp->mp_pages : 1);
			/* clear dirty flag */
			dp->mp_flags &= ~P_DIRTY;
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
		if (!IS_OVERFLOW(dp) || dp->mp_pages == 1) {
			dp->mp_next = txn->mt_env->me_dpages;
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

/** Read the environment parameters of a DB environment before
 * mapping it into memory.
 * @param[in] env the environment handle
 * @param[out] meta address of where to store the meta information
 * @return 0 on success, non-zero on failure.
 */
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

/** Write the environment parameters of a freshly created DB environment.
 * @param[in] env the environment handle
 * @param[out] meta address of where to store the meta information
 * @return 0 on success, non-zero on failure.
 */
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

/** Update the environment info to commit a transaction.
 * @param[in] txn the transaction that's being committed
 * @return 0 on success, non-zero on failure.
 */
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

/** Check both meta pages to see which one is newer.
 * @param[in] env the environment handle
 * @param[out] which address of where to store the meta toggle ID
 * @return 0 on success, non-zero on failure.
 */
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

/** Further setup required for opening an MDB environment
 */
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

	/** The name of the lock file in the DB environment */
#define LOCKNAME	"/lock.mdb"
	/** The name of the data file in the DB environment */
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
	MDB_page *dp;

	if (env == NULL)
		return;

	while (env->me_dpages) {
		dp = env->me_dpages;
		env->me_dpages = dp->mp_next;
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

/* only for aligned ints */
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

/* ints must always be the same size */
static int
cintcmp(const MDB_val *a, const MDB_val *b)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned short *u, *c;
	int x;

	u = a->mv_data + a->mv_size;
	c = b->mv_data + a->mv_size;
	do {
		x = *--u - *--c;
	} while(!x && u > (unsigned short *)a->mv_data);
	return x;
#else
	return memcmp(a->mv_data, b->mv_data, a->mv_size);
#endif
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

	while (p1 > p1_lim) {
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
mdb_search_node(MDB_cursor *mc, MDB_val *key, int *exactp)
{
	unsigned int	 i = 0, nkeys;
	int		 low, high;
	int		 rc = 0;
	MDB_page *mp = mc->mc_pg[mc->mc_top];
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
	cmp = mc->mc_txn->mt_dbxs[mc->mc_dbi].md_cmp;
	if (IS_LEAF2(mp)) {
		nodekey.mv_size = mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad;
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
		if (!IS_LEAF2(mp))
			node = NODEPTR(mp, i);
	}
	if (exactp)
		*exactp = (rc == 0);
	/* store the key index */
	mc->mc_ki[mc->mc_top] = i;
	if (i >= nkeys)
		/* There is no entry larger or equal to the key. */
		return NULL;

	/* nodeptr is fake for LEAF2 */
	return node;
}

static void
cursor_pop_page(MDB_cursor *mc)
{
	MDB_page	*top;

	if (mc->mc_snum) {
		top = mc->mc_pg[mc->mc_top];
		mc->mc_snum--;
		if (mc->mc_snum)
			mc->mc_top--;

		DPRINTF("popped page %lu off db %u cursor %p", top->mp_pgno,
			mc->mc_dbi, (void *) mc);
	}
}

static int
cursor_push_page(MDB_cursor *mc, MDB_page *mp)
{
	DPRINTF("pushing page %lu on db %u cursor %p", mp->mp_pgno,
		mc->mc_dbi, (void *) mc);

	if (mc->mc_snum >= CURSOR_STACK)
		return ENOMEM;

	mc->mc_top = mc->mc_snum++;
	mc->mc_pg[mc->mc_top] = mp;
	mc->mc_ki[mc->mc_top] = 0;

	return MDB_SUCCESS;
}

static int
mdb_get_page(MDB_txn *txn, pgno_t pgno, MDB_page **ret)
{
	MDB_page *p = NULL;

	if (!F_ISSET(txn->mt_flags, MDB_TXN_RDONLY) && txn->mt_u.dirty_list[0].mid) {
		unsigned x;
		x = mdb_mid2l_search(txn->mt_u.dirty_list, pgno);
		if (x <= txn->mt_u.dirty_list[0].mid && txn->mt_u.dirty_list[x].mid == pgno) {
			p = txn->mt_u.dirty_list[x].mptr;
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
mdb_search_page_root(MDB_cursor *mc, MDB_val *key, int modify)
{
	MDB_page	*mp = mc->mc_pg[mc->mc_top];
	DKBUF;
	int rc;


	while (IS_BRANCH(mp)) {
		MDB_node	*node;

		DPRINTF("branch page %lu has %u keys", mp->mp_pgno, NUMKEYS(mp));
		assert(NUMKEYS(mp) > 1);
		DPRINTF("found index 0 to page %lu", NODEPGNO(NODEPTR(mp, 0)));

		if (key == NULL)	/* Initialize cursor to first page. */
			mc->mc_ki[mc->mc_top] = 0;
		else if (key->mv_size > MAXKEYSIZE && key->mv_data == NULL) {
							/* cursor to last page */
			mc->mc_ki[mc->mc_top] = NUMKEYS(mp)-1;
		} else {
			int	 exact;
			node = mdb_search_node(mc, key, &exact);
			if (node == NULL)
				mc->mc_ki[mc->mc_top] = NUMKEYS(mp) - 1;
			else if (!exact) {
				assert(mc->mc_ki[mc->mc_top] > 0);
				mc->mc_ki[mc->mc_top]--;
			}
		}

		if (key)
			DPRINTF("following index %u for key [%s]",
			    mc->mc_ki[mc->mc_top], DKEY(key));
		assert(mc->mc_ki[mc->mc_top] < NUMKEYS(mp));
		node = NODEPTR(mp, mc->mc_ki[mc->mc_top]);

		if ((rc = mdb_get_page(mc->mc_txn, NODEPGNO(node), &mp)))
			return rc;

		if ((rc = cursor_push_page(mc, mp)))
			return rc;

		if (modify) {
			if ((rc = mdb_touch(mc)) != 0)
				return rc;
			mp = mc->mc_pg[mc->mc_top];
		}
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
 * Pushes parent pages on the cursor stack.
 * If key is NULL, search for the lowest page (used by mdb_cursor_first).
 * If modify is true, visited pages are updated with new page numbers.
 */
static int
mdb_search_page(MDB_cursor *mc, MDB_val *key, int modify)
{
	int		 rc;
	pgno_t		 root;

	/* Make sure the txn is still viable, then find the root from
	 * the txn's db table.
	 */
	if (F_ISSET(mc->mc_txn->mt_flags, MDB_TXN_ERROR)) {
		DPUTS("transaction has failed, must abort");
		return EINVAL;
	} else
		root = mc->mc_txn->mt_dbs[mc->mc_dbi].md_root;

	if (root == P_INVALID) {		/* Tree is empty. */
		DPUTS("tree is empty");
		return MDB_NOTFOUND;
	}

	if ((rc = mdb_get_page(mc->mc_txn, root, &mc->mc_pg[0])))
		return rc;

	mc->mc_snum = 1;
	mc->mc_top = 0;

	DPRINTF("db %u root page %lu has flags 0x%X",
		mc->mc_dbi, root, mc->mc_pg[0]->mp_flags);

	if (modify) {
		/* For sub-databases, update main root first */
		if (mc->mc_dbi > MAIN_DBI && !mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dirty) {
			MDB_cursor mc2;
			mc2.mc_txn = mc->mc_txn;
			mc2.mc_dbi = MAIN_DBI;
			rc = mdb_search_page(&mc2, &mc->mc_txn->mt_dbxs[mc->mc_dbi].md_name, 1);
			if (rc)
				return rc;
			mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dirty = 1;
		}
		if (!F_ISSET(mc->mc_pg[0]->mp_flags, P_DIRTY)) {
			if ((rc = mdb_touch(mc)))
				return rc;
			mc->mc_txn->mt_dbs[mc->mc_dbi].md_root = mc->mc_pg[0]->mp_pgno;
		}
	}

	return mdb_search_page_root(mc, key, modify);
}

static int
mdb_read_data(MDB_txn *txn, MDB_node *leaf, MDB_val *data)
{
	MDB_page	*omp;		/* overflow mpage */
	pgno_t		 pgno;
	int rc;

	if (!F_ISSET(leaf->mn_flags, F_BIGDATA)) {
		data->mv_size = NODEDSZ(leaf);
		data->mv_data = NODEDATA(leaf);
		return MDB_SUCCESS;
	}

	/* Read overflow data.
	 */
	data->mv_size = NODEDSZ(leaf);
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
	int exact = 0;
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
mdb_sibling(MDB_cursor *mc, int move_right)
{
	int		 rc;
	unsigned int	ptop;
	MDB_node	*indx;
	MDB_page	*mp;

	if (mc->mc_snum < 2) {
		return MDB_NOTFOUND;		/* root has no siblings */
	}
	ptop = mc->mc_top-1;

	DPRINTF("parent page is page %lu, index %u",
		mc->mc_pg[ptop]->mp_pgno, mc->mc_ki[ptop]);

	cursor_pop_page(mc);
	if (move_right ? (mc->mc_ki[ptop] + 1u >= NUMKEYS(mc->mc_pg[ptop]))
		       : (mc->mc_ki[ptop] == 0)) {
		DPRINTF("no more keys left, moving to %s sibling",
		    move_right ? "right" : "left");
		if ((rc = mdb_sibling(mc, move_right)) != MDB_SUCCESS)
			return rc;
	} else {
		if (move_right)
			mc->mc_ki[ptop]++;
		else
			mc->mc_ki[ptop]--;
		DPRINTF("just moving to %s index key %u",
		    move_right ? "right" : "left", mc->mc_ki[ptop]);
	}
	assert(IS_BRANCH(mc->mc_pg[ptop]));

	indx = NODEPTR(mc->mc_pg[ptop], mc->mc_ki[ptop]);
	if ((rc = mdb_get_page(mc->mc_txn, NODEPGNO(indx), &mp)))
		return rc;;

	cursor_push_page(mc, mp);

	return MDB_SUCCESS;
}

static int
mdb_cursor_next(MDB_cursor *mc, MDB_val *key, MDB_val *data, MDB_cursor_op op)
{
	MDB_page	*mp;
	MDB_node	*leaf;
	int rc;

	if (mc->mc_flags & C_EOF) {
		return MDB_NOTFOUND;
	}

	assert(mc->mc_flags & C_INITIALIZED);

	mp = mc->mc_pg[mc->mc_top];

	if (mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags & MDB_DUPSORT) {
		leaf = NODEPTR(mp, mc->mc_ki[mc->mc_top]);
		if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
			if (op == MDB_NEXT || op == MDB_NEXT_DUP) {
				rc = mdb_cursor_next(&mc->mc_xcursor->mx_cursor, data, NULL, MDB_NEXT);
				if (op != MDB_NEXT || rc == MDB_SUCCESS)
					return rc;
			}
		} else {
			mc->mc_xcursor->mx_cursor.mc_flags = 0;
			if (op == MDB_NEXT_DUP)
				return MDB_NOTFOUND;
		}
	}

	DPRINTF("cursor_next: top page is %lu in cursor %p", mp->mp_pgno, (void *) mc);

	if (mc->mc_ki[mc->mc_top] + 1u >= NUMKEYS(mp)) {
		DPUTS("=====> move to next sibling page");
		if (mdb_sibling(mc, 1) != MDB_SUCCESS) {
			mc->mc_flags |= C_EOF;
			return MDB_NOTFOUND;
		}
		mp = mc->mc_pg[mc->mc_top];
		DPRINTF("next page is %lu, key index %u", mp->mp_pgno, mc->mc_ki[mc->mc_top]);
	} else
		mc->mc_ki[mc->mc_top]++;

	DPRINTF("==> cursor points to page %lu with %u keys, key index %u",
	    mp->mp_pgno, NUMKEYS(mp), mc->mc_ki[mc->mc_top]);

	if (IS_LEAF2(mp)) {
		key->mv_size = mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad;
		key->mv_data = LEAF2KEY(mp, mc->mc_ki[mc->mc_top], key->mv_size);
		return MDB_SUCCESS;
	}

	assert(IS_LEAF(mp));
	leaf = NODEPTR(mp, mc->mc_ki[mc->mc_top]);

	if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
		mdb_xcursor_init1(mc, leaf);
	}
	if (data) {
		if ((rc = mdb_read_data(mc->mc_txn, leaf, data) != MDB_SUCCESS))
			return rc;

		if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
			rc = mdb_cursor_first(&mc->mc_xcursor->mx_cursor, data, NULL);
			if (rc != MDB_SUCCESS)
				return rc;
		}
	}

	MDB_SET_KEY(leaf, key);
	return MDB_SUCCESS;
}

static int
mdb_cursor_prev(MDB_cursor *mc, MDB_val *key, MDB_val *data, MDB_cursor_op op)
{
	MDB_page	*mp;
	MDB_node	*leaf;
	int rc;

	assert(mc->mc_flags & C_INITIALIZED);

	mp = mc->mc_pg[mc->mc_top];

	if (mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags & MDB_DUPSORT) {
		leaf = NODEPTR(mp, mc->mc_ki[mc->mc_top]);
		if (op == MDB_PREV || op == MDB_PREV_DUP) {
			if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
				rc = mdb_cursor_prev(&mc->mc_xcursor->mx_cursor, data, NULL, MDB_PREV);
				if (op != MDB_PREV || rc == MDB_SUCCESS)
					return rc;
			} else {
				mc->mc_xcursor->mx_cursor.mc_flags = 0;
				if (op == MDB_PREV_DUP)
					return MDB_NOTFOUND;
			}
		}
	}

	DPRINTF("cursor_prev: top page is %lu in cursor %p", mp->mp_pgno, (void *) mc);

	if (mc->mc_ki[mc->mc_top] == 0)  {
		DPUTS("=====> move to prev sibling page");
		if (mdb_sibling(mc, 0) != MDB_SUCCESS) {
			mc->mc_flags &= ~C_INITIALIZED;
			return MDB_NOTFOUND;
		}
		mp = mc->mc_pg[mc->mc_top];
		mc->mc_ki[mc->mc_top] = NUMKEYS(mp) - 1;
		DPRINTF("prev page is %lu, key index %u", mp->mp_pgno, mc->mc_ki[mc->mc_top]);
	} else
		mc->mc_ki[mc->mc_top]--;

	mc->mc_flags &= ~C_EOF;

	DPRINTF("==> cursor points to page %lu with %u keys, key index %u",
	    mp->mp_pgno, NUMKEYS(mp), mc->mc_ki[mc->mc_top]);

	if (IS_LEAF2(mp)) {
		key->mv_size = mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad;
		key->mv_data = LEAF2KEY(mp, mc->mc_ki[mc->mc_top], key->mv_size);
		return MDB_SUCCESS;
	}

	assert(IS_LEAF(mp));
	leaf = NODEPTR(mp, mc->mc_ki[mc->mc_top]);

	if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
		mdb_xcursor_init1(mc, leaf);
	}
	if (data) {
		if ((rc = mdb_read_data(mc->mc_txn, leaf, data) != MDB_SUCCESS))
			return rc;

		if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
			rc = mdb_cursor_last(&mc->mc_xcursor->mx_cursor, data, NULL);
			if (rc != MDB_SUCCESS)
				return rc;
		}
	}

	MDB_SET_KEY(leaf, key);
	return MDB_SUCCESS;
}

static int
mdb_cursor_set(MDB_cursor *mc, MDB_val *key, MDB_val *data,
    MDB_cursor_op op, int *exactp)
{
	int		 rc;
	MDB_node	*leaf;
	DKBUF;

	assert(mc);
	assert(key);
	assert(key->mv_size > 0);

	/* See if we're already on the right page */
	if (mc->mc_flags & C_INITIALIZED) {
		MDB_val nodekey;

		if (mc->mc_pg[mc->mc_top]->mp_flags & P_LEAF2) {
			nodekey.mv_size = mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad;
			nodekey.mv_data = LEAF2KEY(mc->mc_pg[mc->mc_top], 0, nodekey.mv_size);
		} else {
			leaf = NODEPTR(mc->mc_pg[mc->mc_top], 0);
			MDB_SET_KEY(leaf, &nodekey);
		}
		rc = mc->mc_txn->mt_dbxs[mc->mc_dbi].md_cmp(key, &nodekey);
		if (rc == 0) {
			/* Probably happens rarely, but first node on the page
			 * was the one we wanted.
			 */
			mc->mc_ki[mc->mc_top] = 0;
set1:
			if (exactp)
				*exactp = 1;
			leaf = NODEPTR(mc->mc_pg[mc->mc_top], mc->mc_ki[mc->mc_top]);
			goto set3;
		}
		if (rc > 0) {
			unsigned int i;
			if (NUMKEYS(mc->mc_pg[mc->mc_top]) > 1) {
				if (mc->mc_pg[mc->mc_top]->mp_flags & P_LEAF2) {
					nodekey.mv_data = LEAF2KEY(mc->mc_pg[mc->mc_top],
						 NUMKEYS(mc->mc_pg[mc->mc_top])-1, nodekey.mv_size);
				} else {
					leaf = NODEPTR(mc->mc_pg[mc->mc_top], NUMKEYS(mc->mc_pg[mc->mc_top])-1);
					MDB_SET_KEY(leaf, &nodekey);
				}
				rc = mc->mc_txn->mt_dbxs[mc->mc_dbi].md_cmp(key, &nodekey);
				if (rc == 0) {
					/* last node was the one we wanted */
					mc->mc_ki[mc->mc_top] = NUMKEYS(mc->mc_pg[mc->mc_top])-1;
					goto set1;
				}
				if (rc < 0) {
					/* This is definitely the right page, skip search_page */
					rc = 0;
					goto set2;
				}
			}
			/* If any parents have right-sibs, search.
			 * Otherwise, there's nothing further.
			 */
			for (i=0; i<mc->mc_top; i++)
				if (mc->mc_ki[i] <
					NUMKEYS(mc->mc_pg[i])-1)
					break;
			if (i == mc->mc_top) {
				/* There are no other pages */
				mc->mc_ki[mc->mc_top] = NUMKEYS(mc->mc_pg[mc->mc_top]);
				return MDB_NOTFOUND;
			}
		}
	}

	rc = mdb_search_page(mc, key, 0);
	if (rc != MDB_SUCCESS)
		return rc;

	assert(IS_LEAF(mc->mc_pg[mc->mc_top]));

set2:
	leaf = mdb_search_node(mc, key, exactp);
	if (exactp != NULL && !*exactp) {
		/* MDB_SET specified and not an exact match. */
		return MDB_NOTFOUND;
	}

	if (leaf == NULL) {
		DPUTS("===> inexact leaf not found, goto sibling");
		if ((rc = mdb_sibling(mc, 1)) != MDB_SUCCESS)
			return rc;		/* no entries matched */
		mc->mc_ki[mc->mc_top] = 0;
		assert(IS_LEAF(mc->mc_pg[mc->mc_top]));
		leaf = NODEPTR(mc->mc_pg[mc->mc_top], 0);
	}

set3:
	mc->mc_flags |= C_INITIALIZED;
	mc->mc_flags &= ~C_EOF;

	if (IS_LEAF2(mc->mc_pg[mc->mc_top])) {
		key->mv_size = mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad;
		key->mv_data = LEAF2KEY(mc->mc_pg[mc->mc_top], mc->mc_ki[mc->mc_top], key->mv_size);
		return MDB_SUCCESS;
	}

	if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
		mdb_xcursor_init1(mc, leaf);
	}
	if (data) {
		if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
			if (op == MDB_SET || op == MDB_SET_RANGE) {
				rc = mdb_cursor_first(&mc->mc_xcursor->mx_cursor, data, NULL);
			} else {
				int ex2, *ex2p;
				if (op == MDB_GET_BOTH) {
					ex2p = &ex2;
					ex2 = 0;
				} else {
					ex2p = NULL;
				}
				rc = mdb_cursor_set(&mc->mc_xcursor->mx_cursor, data, NULL, MDB_SET_RANGE, ex2p);
				if (rc != MDB_SUCCESS)
					return rc;
			}
		} else if (op == MDB_GET_BOTH || op == MDB_GET_BOTH_RANGE) {
			MDB_val d2;
			if ((rc = mdb_read_data(mc->mc_txn, leaf, &d2)) != MDB_SUCCESS)
				return rc;
			rc = mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dcmp(data, &d2);
			if (rc) {
				if (op == MDB_GET_BOTH || rc > 0)
					return MDB_NOTFOUND;
			}

		} else {
			if ((rc = mdb_read_data(mc->mc_txn, leaf, data)) != MDB_SUCCESS)
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
mdb_cursor_first(MDB_cursor *mc, MDB_val *key, MDB_val *data)
{
	int		 rc;
	MDB_node	*leaf;

	rc = mdb_search_page(mc, NULL, 0);
	if (rc != MDB_SUCCESS)
		return rc;
	assert(IS_LEAF(mc->mc_pg[mc->mc_top]));

	leaf = NODEPTR(mc->mc_pg[mc->mc_top], 0);
	mc->mc_flags |= C_INITIALIZED;
	mc->mc_flags &= ~C_EOF;

	if (IS_LEAF2(mc->mc_pg[mc->mc_top])) {
		key->mv_size = mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad;
		key->mv_data = LEAF2KEY(mc->mc_pg[mc->mc_top], 0, key->mv_size);
		return MDB_SUCCESS;
	}

	if (data) {
		if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
			mdb_xcursor_init1(mc, leaf);
			rc = mdb_cursor_first(&mc->mc_xcursor->mx_cursor, data, NULL);
			if (rc)
				return rc;
		} else {
			if (mc->mc_xcursor)
				mc->mc_xcursor->mx_cursor.mc_flags = 0;
			if ((rc = mdb_read_data(mc->mc_txn, leaf, data)) != MDB_SUCCESS)
				return rc;
		}
	}
	MDB_SET_KEY(leaf, key);
	return MDB_SUCCESS;
}

static int
mdb_cursor_last(MDB_cursor *mc, MDB_val *key, MDB_val *data)
{
	int		 rc;
	MDB_node	*leaf;
	MDB_val	lkey;

	lkey.mv_size = MAXKEYSIZE+1;
	lkey.mv_data = NULL;

	rc = mdb_search_page(mc, &lkey, 0);
	if (rc != MDB_SUCCESS)
		return rc;
	assert(IS_LEAF(mc->mc_pg[mc->mc_top]));

	leaf = NODEPTR(mc->mc_pg[mc->mc_top], NUMKEYS(mc->mc_pg[mc->mc_top])-1);
	mc->mc_flags |= C_INITIALIZED;
	mc->mc_flags &= ~C_EOF;

	mc->mc_ki[mc->mc_top] = NUMKEYS(mc->mc_pg[mc->mc_top]) - 1;

	if (IS_LEAF2(mc->mc_pg[mc->mc_top])) {
		key->mv_size = mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad;
		key->mv_data = LEAF2KEY(mc->mc_pg[mc->mc_top], mc->mc_ki[mc->mc_top], key->mv_size);
		return MDB_SUCCESS;
	}

	if (data) {
		if (F_ISSET(leaf->mn_flags, F_DUPDATA)) {
			mdb_xcursor_init1(mc, leaf);
			rc = mdb_cursor_last(&mc->mc_xcursor->mx_cursor, data, NULL);
			if (rc)
				return rc;
		} else {
			if ((rc = mdb_read_data(mc->mc_txn, leaf, data)) != MDB_SUCCESS)
				return rc;
		}
	}

	MDB_SET_KEY(leaf, key);
	return MDB_SUCCESS;
}

int
mdb_cursor_get(MDB_cursor *mc, MDB_val *key, MDB_val *data,
    MDB_cursor_op op)
{
	int		 rc;
	int		 exact = 0;

	assert(mc);

	switch (op) {
	case MDB_GET_BOTH:
	case MDB_GET_BOTH_RANGE:
		if (data == NULL || mc->mc_xcursor == NULL) {
			rc = EINVAL;
			break;
		}
		/* FALLTHRU */
	case MDB_SET:
	case MDB_SET_RANGE:
		if (key == NULL || key->mv_size == 0 || key->mv_size > MAXKEYSIZE) {
			rc = EINVAL;
		} else if (op == MDB_SET_RANGE)
			rc = mdb_cursor_set(mc, key, data, op, NULL);
		else
			rc = mdb_cursor_set(mc, key, data, op, &exact);
		break;
	case MDB_GET_MULTIPLE:
		if (data == NULL ||
			!(mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags & MDB_DUPFIXED) ||
			!(mc->mc_flags & C_INITIALIZED)) {
			rc = EINVAL;
			break;
		}
		rc = MDB_SUCCESS;
		if (!(mc->mc_xcursor->mx_cursor.mc_flags & C_INITIALIZED) ||
			(mc->mc_xcursor->mx_cursor.mc_flags & C_EOF))
			break;
		goto fetchm;
	case MDB_NEXT_MULTIPLE:
		if (data == NULL ||
			!(mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags & MDB_DUPFIXED)) {
			rc = EINVAL;
			break;
		}
		if (!(mc->mc_flags & C_INITIALIZED))
			rc = mdb_cursor_first(mc, key, data);
		else
			rc = mdb_cursor_next(mc, key, data, MDB_NEXT_DUP);
		if (rc == MDB_SUCCESS) {
			if (mc->mc_xcursor->mx_cursor.mc_flags & C_INITIALIZED) {
				MDB_cursor *mx;
fetchm:
				mx = &mc->mc_xcursor->mx_cursor;
				data->mv_size = NUMKEYS(mx->mc_pg[mx->mc_top]) *
					mx->mc_txn->mt_dbs[mx->mc_dbi].md_pad;
				data->mv_data = METADATA(mx->mc_pg[mx->mc_top]);
				mx->mc_ki[mx->mc_top] = NUMKEYS(mx->mc_pg[mx->mc_top])-1;
			} else {
				rc = MDB_NOTFOUND;
			}
		}
		break;
	case MDB_NEXT:
	case MDB_NEXT_DUP:
	case MDB_NEXT_NODUP:
		if (!(mc->mc_flags & C_INITIALIZED))
			rc = mdb_cursor_first(mc, key, data);
		else
			rc = mdb_cursor_next(mc, key, data, op);
		break;
	case MDB_PREV:
	case MDB_PREV_DUP:
	case MDB_PREV_NODUP:
		if (!(mc->mc_flags & C_INITIALIZED) || (mc->mc_flags & C_EOF))
			rc = mdb_cursor_last(mc, key, data);
		else
			rc = mdb_cursor_prev(mc, key, data, op);
		break;
	case MDB_FIRST:
		rc = mdb_cursor_first(mc, key, data);
		break;
	case MDB_FIRST_DUP:
		if (data == NULL ||
			!(mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags & MDB_DUPSORT) ||
			!(mc->mc_flags & C_INITIALIZED) ||
			!(mc->mc_xcursor->mx_cursor.mc_flags & C_INITIALIZED)) {
			rc = EINVAL;
			break;
		}
		rc = mdb_cursor_first(&mc->mc_xcursor->mx_cursor, data, NULL);
		break;
	case MDB_LAST:
		rc = mdb_cursor_last(mc, key, data);
		break;
	case MDB_LAST_DUP:
		if (data == NULL ||
			!(mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags & MDB_DUPSORT) ||
			!(mc->mc_flags & C_INITIALIZED) ||
			!(mc->mc_xcursor->mx_cursor.mc_flags & C_INITIALIZED)) {
			rc = EINVAL;
			break;
		}
		rc = mdb_cursor_last(&mc->mc_xcursor->mx_cursor, data, NULL);
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
	int rc;

	if (mc->mc_dbi > MAIN_DBI && !mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dirty) {
		MDB_cursor mc2;
		mc2.mc_txn = mc->mc_txn;
		mc2.mc_dbi = MAIN_DBI;
		rc = mdb_search_page(&mc2, &mc->mc_txn->mt_dbxs[mc->mc_dbi].md_name, 1);
		if (rc) return rc;
		mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dirty = 1;
	}
	for (mc->mc_top = 0; mc->mc_top < mc->mc_snum; mc->mc_top++) {
		if (!F_ISSET(mc->mc_pg[mc->mc_top]->mp_flags, P_DIRTY)) {
			rc = mdb_touch(mc);
			if (rc) return rc;
			if (!mc->mc_top) {
				mc->mc_txn->mt_dbs[mc->mc_dbi].md_root =
					mc->mc_pg[mc->mc_top]->mp_pgno;
			}
		}
	}
	mc->mc_top = mc->mc_snum-1;
	return MDB_SUCCESS;
}

int
mdb_cursor_put(MDB_cursor *mc, MDB_val *key, MDB_val *data,
    unsigned int flags)
{
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
		MDB_page *np;
		/* new database, write a root leaf page */
		DPUTS("allocating new root leaf page");
		if ((np = mdb_new_page(mc, P_LEAF, 1)) == NULL) {
			return ENOMEM;
		}
		mc->mc_snum = 0;
		cursor_push_page(mc, np);
		mc->mc_txn->mt_dbs[mc->mc_dbi].md_root = np->mp_pgno;
		mc->mc_txn->mt_dbs[mc->mc_dbi].md_depth++;
		mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dirty = 1;
		if ((mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags & (MDB_DUPSORT|MDB_DUPFIXED))
			== MDB_DUPFIXED)
			np->mp_flags |= P_LEAF2;
		mc->mc_flags |= C_INITIALIZED;
		rc = MDB_NOTFOUND;
		goto top;
	} else {
		int exact = 0;
		MDB_val d2;
		rc = mdb_cursor_set(mc, key, &d2, MDB_SET, &exact);
		if (flags == MDB_NOOVERWRITE && rc == 0) {
			DPRINTF("duplicate key [%s]", DKEY(key));
			*data = d2;
			return MDB_KEYEXIST;
		}
		if (rc && rc != MDB_NOTFOUND)
			return rc;
	}

	/* Cursor is positioned, now make sure all pages are writable */
	rc2 = mdb_cursor_touch(mc);
	if (rc2) return rc2;

top:
	/* The key already exists */
	if (rc == MDB_SUCCESS) {
		/* there's only a key anyway, so this is a no-op */
		if (IS_LEAF2(mc->mc_pg[mc->mc_top])) {
			unsigned int ksize = mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad;
			if (key->mv_size != ksize)
				return EINVAL;
			if (flags == MDB_CURRENT) {
				char *ptr = LEAF2KEY(mc->mc_pg[mc->mc_top], mc->mc_ki[mc->mc_top], ksize);
				memcpy(ptr, key->mv_data, ksize);
			}
			return MDB_SUCCESS;
		}

		leaf = NODEPTR(mc->mc_pg[mc->mc_top], mc->mc_ki[mc->mc_top]);

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
				mdb_del_node(mc->mc_pg[mc->mc_top], mc->mc_ki[mc->mc_top], 0);
				do_sub = 1;
				rdata = &xdata;
				xdata.mv_size = sizeof(MDB_db);
				xdata.mv_data = &dummy;
				/* new sub-DB, must fully init xcursor */
				if (flags == MDB_CURRENT)
					flags = 0;
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
		mdb_del_node(mc->mc_pg[mc->mc_top], mc->mc_ki[mc->mc_top], 0);
	} else {
		DPRINTF("inserting key at index %i", mc->mc_ki[mc->mc_top]);
	}

	rdata = data;

new_sub:
	nsize = IS_LEAF2(mc->mc_pg[mc->mc_top]) ? key->mv_size : mdb_leaf_size(mc->mc_txn->mt_env, key, rdata);
	if (SIZELEFT(mc->mc_pg[mc->mc_top]) < nsize) {
		rc = mdb_split(mc, key, rdata, P_INVALID);
	} else {
		/* There is room already in this leaf page. */
		rc = mdb_add_node(mc, mc->mc_ki[mc->mc_top], key, rdata, 0, 0);
	}

	if (rc != MDB_SUCCESS)
		mc->mc_txn->mt_flags |= MDB_TXN_ERROR;
	else {
		/* Remember if we just added a subdatabase */
		if (flags & F_SUBDATA) {
			leaf = NODEPTR(mc->mc_pg[mc->mc_top], mc->mc_ki[mc->mc_top]);
			leaf->mn_flags |= F_SUBDATA;
		}

		/* Now store the actual data in the child DB. Note that we're
		 * storing the user data in the keys field, so there are strict
		 * size limits on dupdata. The actual data fields of the child
		 * DB are all zero size.
		 */
		if (do_sub) {
			leaf = NODEPTR(mc->mc_pg[mc->mc_top], mc->mc_ki[mc->mc_top]);
put_sub:
			if (flags == MDB_CURRENT)
				mdb_xcursor_init2(mc);
			else
				mdb_xcursor_init1(mc, leaf);
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
	MDB_node	*leaf;
	int rc;

	if (F_ISSET(mc->mc_txn->mt_flags, MDB_TXN_RDONLY))
		return EACCES;

	if (!mc->mc_flags & C_INITIALIZED)
		return EINVAL;

	rc = mdb_cursor_touch(mc);
	if (rc) return rc;

	leaf = NODEPTR(mc->mc_pg[mc->mc_top], mc->mc_ki[mc->mc_top]);

	if (!IS_LEAF2(mc->mc_pg[mc->mc_top]) && F_ISSET(leaf->mn_flags, F_DUPDATA)) {
		if (flags != MDB_NODUPDATA) {
			mdb_xcursor_init2(mc);
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
		rc = mdb_search_page(&mc->mc_xcursor->mx_cursor, NULL, 0);
		if (rc == MDB_SUCCESS) {
			MDB_node *ni;
			MDB_cursor *mx;
			unsigned int i;

			mx = &mc->mc_xcursor->mx_cursor;
			mc->mc_txn->mt_dbs[mc->mc_dbi].md_entries -=
				mx->mc_txn->mt_dbs[mx->mc_dbi].md_entries;

			cursor_pop_page(mx);
			if (mx->mc_snum) {
				while (mx->mc_snum > 1) {
					for (i=0; i<NUMKEYS(mx->mc_pg[mx->mc_top]); i++) {
						pgno_t pg;
						ni = NODEPTR(mx->mc_pg[mx->mc_top], i);
						pg = NODEPGNO(ni);
						/* free it */
						mdb_midl_append(mc->mc_txn->mt_free_pgs, pg);
					}
					rc = mdb_sibling(mx, 1);
					if (rc) break;
				}
			}
			/* free it */
			mdb_midl_append(mc->mc_txn->mt_free_pgs,
				mx->mc_txn->mt_dbs[mx->mc_dbi].md_root);
		}
	}

	return mdb_del0(mc, leaf);
}

/* Allocate a page and initialize it
 */
static MDB_page *
mdb_new_page(MDB_cursor *mc, uint32_t flags, int num)
{
	MDB_page	*np;

	if ((np = mdb_alloc_page(mc, num)) == NULL)
		return NULL;
	DPRINTF("allocated new mpage %lu, page size %u",
	    np->mp_pgno, mc->mc_txn->mt_env->me_psize);
	np->mp_flags = flags | P_DIRTY;
	np->mp_lower = PAGEHDRSZ;
	np->mp_upper = mc->mc_txn->mt_env->me_psize;

	if (IS_BRANCH(np))
		mc->mc_txn->mt_dbs[mc->mc_dbi].md_branch_pages++;
	else if (IS_LEAF(np))
		mc->mc_txn->mt_dbs[mc->mc_dbi].md_leaf_pages++;
	else if (IS_OVERFLOW(np)) {
		mc->mc_txn->mt_dbs[mc->mc_dbi].md_overflow_pages += num;
		np->mp_pages = num;
	}

	return np;
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
	sz += sz & 1;

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
mdb_add_node(MDB_cursor *mc, indx_t indx,
    MDB_val *key, MDB_val *data, pgno_t pgno, uint8_t flags)
{
	unsigned int	 i;
	size_t		 node_size = NODESIZE;
	indx_t		 ofs;
	MDB_node	*node;
	MDB_page	*mp = mc->mc_pg[mc->mc_top];
	MDB_page	*ofp = NULL;		/* overflow page */
	DKBUF;

	assert(mp->mp_upper >= mp->mp_lower);

	DPRINTF("add to %s page %lu index %i, data size %zu key size %zu [%s]",
	    IS_LEAF(mp) ? "leaf" : "branch",
	    mp->mp_pgno, indx, data ? data->mv_size : 0,
		key ? key->mv_size : 0, key ? DKEY(key) : NULL);

	if (IS_LEAF2(mp)) {
		/* Move higher keys up one slot. */
		int ksize = mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad, dif;
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
		} else if (data->mv_size >= mc->mc_txn->mt_env->me_psize / MDB_MINKEYS) {
			int ovpages = OVPAGES(data->mv_size, mc->mc_txn->mt_env->me_psize);
			/* Put data on overflow page. */
			DPRINTF("data size is %zu, put on overflow page",
			    data->mv_size);
			node_size += sizeof(pgno_t);
			if ((ofp = mdb_new_page(mc, P_OVERFLOW, ovpages)) == NULL)
				return ENOMEM;
			DPRINTF("allocated overflow page %lu", ofp->mp_pgno);
			flags |= F_BIGDATA;
		} else {
			node_size += data->mv_size;
		}
	}
	node_size += node_size & 1;

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
		SETDSZ(node,data->mv_size);
	else
		SETPGNO(node,pgno);

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
			memcpy(node->mn_data + key->mv_size, &ofp->mp_pgno,
			    sizeof(pgno_t));
			memcpy(METADATA(ofp), data->mv_data, data->mv_size);
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
	sz += sz & 1;

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
	mx->mx_txn.mt_u = mc->mc_txn->mt_u;

	mx->mx_cursor.mc_xcursor = NULL;
	mx->mx_cursor.mc_txn = &mx->mx_txn;
	mx->mx_cursor.mc_dbi = dbn+1;
}

static void
mdb_xcursor_init1(MDB_cursor *mc, MDB_node *node)
{
	MDB_db *db = NODEDATA(node);
	MDB_xcursor *mx = mc->mc_xcursor;
	MDB_dbi dbn;
	mx->mx_dbs[0] = mc->mc_txn->mt_dbs[0];
	mx->mx_dbs[1] = mc->mc_txn->mt_dbs[1];
	if (mc->mc_dbi > 1) {
		mx->mx_dbs[2] = mc->mc_txn->mt_dbs[mc->mc_dbi];
		mx->mx_dbxs[2].md_dirty = mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dirty;
		dbn = 3;
	} else {
		dbn = 2;
	}
	DPRINTF("Sub-db %u for db %u root page %lu", dbn, mc->mc_dbi, db->md_root);
	mx->mx_dbs[dbn] = *db;
	if (F_ISSET(mc->mc_pg[mc->mc_top]->mp_flags, P_DIRTY))
		mx->mx_dbxs[dbn].md_dirty = 1;
	mx->mx_dbxs[dbn].md_name.mv_data = NODEKEY(node);
	mx->mx_dbxs[dbn].md_name.mv_size = node->mn_ksize;
	mx->mx_txn.mt_next_pgno = mc->mc_txn->mt_next_pgno;
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
		mx->mx_dbxs[2].md_dirty = mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dirty;
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
	if (mc->mc_dbi > 1) {
		mc->mc_txn->mt_dbs[mc->mc_dbi] = mx->mx_dbs[2];
		mc->mc_txn->mt_dbxs[mc->mc_dbi].md_dirty = mx->mx_dbxs[2].md_dirty;
	}
}

int
mdb_cursor_open(MDB_txn *txn, MDB_dbi dbi, MDB_cursor **ret)
{
	MDB_cursor	*mc;
	size_t size = sizeof(MDB_cursor);

	if (txn == NULL || ret == NULL || !dbi || dbi >= txn->mt_numdbs)
		return EINVAL;

	if (txn->mt_dbs[dbi].md_flags & MDB_DUPSORT)
		size += sizeof(MDB_xcursor);

	if ((mc = calloc(1, size)) != NULL) {
		mc->mc_dbi = dbi;
		mc->mc_txn = txn;
		if (txn->mt_dbs[dbi].md_flags & MDB_DUPSORT) {
			MDB_xcursor *mx = (MDB_xcursor *)(mc + 1);
			mc->mc_xcursor = mx;
			mdb_xcursor_init0(mc);
		}
	} else {
		return ENOMEM;
	}

	*ret = mc;

	return MDB_SUCCESS;
}

/* Return the count of duplicate data items for the current key */
int
mdb_cursor_count(MDB_cursor *mc, unsigned long *countp)
{
	MDB_node	*leaf;

	if (mc == NULL || countp == NULL)
		return EINVAL;

	if (!(mc->mc_txn->mt_dbs[mc->mc_dbi].md_flags & MDB_DUPSORT))
		return EINVAL;

	leaf = NODEPTR(mc->mc_pg[mc->mc_top], mc->mc_ki[mc->mc_top]);
	if (!F_ISSET(leaf->mn_flags, F_DUPDATA)) {
		*countp = 1;
	} else {
		if (!(mc->mc_xcursor->mx_cursor.mc_flags & C_INITIALIZED))
			return EINVAL;

		*countp = mc->mc_xcursor->mx_txn.mt_dbs[mc->mc_xcursor->mx_cursor.mc_dbi].md_entries;
	}
	return MDB_SUCCESS;
}

void
mdb_cursor_close(MDB_cursor *mc)
{
	if (mc != NULL) {
		free(mc);
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

/* Move a node from csrc to cdst.
 */
static int
mdb_move_node(MDB_cursor *csrc, MDB_cursor *cdst)
{
	int			 rc;
	MDB_node		*srcnode;
	MDB_val		 key, data;
	DKBUF;

	/* Mark src and dst as dirty. */
	if ((rc = mdb_touch(csrc)) ||
	    (rc = mdb_touch(cdst)))
		return rc;;

	if (IS_LEAF2(csrc->mc_pg[csrc->mc_top])) {
		srcnode = NODEPTR(csrc->mc_pg[csrc->mc_top], 0);	/* fake */
		key.mv_size = csrc->mc_txn->mt_dbs[csrc->mc_dbi].md_pad;
		key.mv_data = LEAF2KEY(csrc->mc_pg[csrc->mc_top], csrc->mc_ki[csrc->mc_top], key.mv_size);
		data.mv_size = 0;
		data.mv_data = NULL;
	} else {
		if (csrc->mc_ki[csrc->mc_top] == 0 && IS_BRANCH(csrc->mc_pg[csrc->mc_top])) {
			unsigned int snum = csrc->mc_snum;
			/* must find the lowest key below src */
			mdb_search_page_root(csrc, NULL, 0);
			srcnode = NODEPTR(csrc->mc_pg[csrc->mc_top], 0);
			csrc->mc_snum = snum--;
			csrc->mc_top = snum;
		} else {
			srcnode = NODEPTR(csrc->mc_pg[csrc->mc_top], csrc->mc_ki[csrc->mc_top]);
		}
		key.mv_size = NODEKSZ(srcnode);
		key.mv_data = NODEKEY(srcnode);
		data.mv_size = NODEDSZ(srcnode);
		data.mv_data = NODEDATA(srcnode);
	}
	DPRINTF("moving %s node %u [%s] on page %lu to node %u on page %lu",
	    IS_LEAF(csrc->mc_pg[csrc->mc_top]) ? "leaf" : "branch",
	    csrc->mc_ki[csrc->mc_top],
		DKEY(&key),
	    csrc->mc_pg[csrc->mc_top]->mp_pgno,
	    cdst->mc_ki[cdst->mc_top], cdst->mc_pg[cdst->mc_top]->mp_pgno);

	/* Add the node to the destination page.
	 */
	rc = mdb_add_node(cdst, cdst->mc_ki[cdst->mc_top], &key, &data, NODEPGNO(srcnode),
	    srcnode->mn_flags);
	if (rc != MDB_SUCCESS)
		return rc;

	/* Delete the node from the source page.
	 */
	mdb_del_node(csrc->mc_pg[csrc->mc_top], csrc->mc_ki[csrc->mc_top], key.mv_size);

	/* Update the parent separators.
	 */
	if (csrc->mc_ki[csrc->mc_top] == 0) {
		if (csrc->mc_ki[csrc->mc_top-1] != 0) {
			if (IS_LEAF2(csrc->mc_pg[csrc->mc_top])) {
				key.mv_data = LEAF2KEY(csrc->mc_pg[csrc->mc_top], csrc->mc_ki[csrc->mc_top], key.mv_size);
			} else {
				srcnode = NODEPTR(csrc->mc_pg[csrc->mc_top], csrc->mc_ki[csrc->mc_top]);
				key.mv_size = NODEKSZ(srcnode);
				key.mv_data = NODEKEY(srcnode);
			}
			DPRINTF("update separator for source page %lu to [%s]",
				csrc->mc_pg[csrc->mc_top]->mp_pgno, DKEY(&key));
			if ((rc = mdb_update_key(csrc->mc_pg[csrc->mc_top-1], csrc->mc_ki[csrc->mc_top-1],
				&key)) != MDB_SUCCESS)
				return rc;
		}
		if (IS_BRANCH(csrc->mc_pg[csrc->mc_top])) {
			MDB_val	 nullkey;
			nullkey.mv_size = 0;
			assert(mdb_update_key(csrc->mc_pg[csrc->mc_top], 0, &nullkey) == MDB_SUCCESS);
		}
	}

	if (cdst->mc_ki[cdst->mc_top] == 0) {
		if (cdst->mc_ki[cdst->mc_top-1] != 0) {
			if (IS_LEAF2(csrc->mc_pg[csrc->mc_top])) {
				key.mv_data = LEAF2KEY(cdst->mc_pg[cdst->mc_top], 0, key.mv_size);
			} else {
				srcnode = NODEPTR(cdst->mc_pg[cdst->mc_top], 0);
				key.mv_size = NODEKSZ(srcnode);
				key.mv_data = NODEKEY(srcnode);
			}
			DPRINTF("update separator for destination page %lu to [%s]",
				cdst->mc_pg[cdst->mc_top]->mp_pgno, DKEY(&key));
			if ((rc = mdb_update_key(cdst->mc_pg[cdst->mc_top-1], cdst->mc_ki[cdst->mc_top-1],
				&key)) != MDB_SUCCESS)
				return rc;
		}
		if (IS_BRANCH(cdst->mc_pg[cdst->mc_top])) {
			MDB_val	 nullkey;
			nullkey.mv_size = 0;
			assert(mdb_update_key(cdst->mc_pg[cdst->mc_top], 0, &nullkey) == MDB_SUCCESS);
		}
	}

	return MDB_SUCCESS;
}

static int
mdb_merge(MDB_cursor *csrc, MDB_cursor *cdst)
{
	int			 rc;
	indx_t			 i, j;
	MDB_node		*srcnode;
	MDB_val		 key, data;

	DPRINTF("merging page %lu into %lu", csrc->mc_pg[csrc->mc_top]->mp_pgno, cdst->mc_pg[cdst->mc_top]->mp_pgno);

	assert(csrc->mc_snum > 1);	/* can't merge root page */
	assert(cdst->mc_snum > 1);

	/* Mark dst as dirty. */
	if ((rc = mdb_touch(cdst)))
		return rc;

	/* Move all nodes from src to dst.
	 */
	j = NUMKEYS(cdst->mc_pg[cdst->mc_top]);
	if (IS_LEAF2(csrc->mc_pg[csrc->mc_top])) {
		key.mv_size = csrc->mc_txn->mt_dbs[csrc->mc_dbi].md_pad;
		key.mv_data = METADATA(csrc->mc_pg[csrc->mc_top]);
		for (i = 0; i < NUMKEYS(csrc->mc_pg[csrc->mc_top]); i++, j++) {
			rc = mdb_add_node(cdst, j, &key, NULL, 0, 0);
			if (rc != MDB_SUCCESS)
				return rc;
			key.mv_data = (char *)key.mv_data + key.mv_size;
		}
	} else {
		for (i = 0; i < NUMKEYS(csrc->mc_pg[csrc->mc_top]); i++, j++) {
			srcnode = NODEPTR(csrc->mc_pg[csrc->mc_top], i);

			key.mv_size = srcnode->mn_ksize;
			key.mv_data = NODEKEY(srcnode);
			data.mv_size = NODEDSZ(srcnode);
			data.mv_data = NODEDATA(srcnode);
			rc = mdb_add_node(cdst, j, &key, &data, NODEPGNO(srcnode), srcnode->mn_flags);
			if (rc != MDB_SUCCESS)
				return rc;
		}
	}

	DPRINTF("dst page %lu now has %u keys (%.1f%% filled)",
	    cdst->mc_pg[cdst->mc_top]->mp_pgno, NUMKEYS(cdst->mc_pg[cdst->mc_top]), (float)PAGEFILL(cdst->mc_txn->mt_env, cdst->mc_pg[cdst->mc_top]) / 10);

	/* Unlink the src page from parent and add to free list.
	 */
	mdb_del_node(csrc->mc_pg[csrc->mc_top-1], csrc->mc_ki[csrc->mc_top-1], 0);
	if (csrc->mc_ki[csrc->mc_top-1] == 0) {
		key.mv_size = 0;
		if ((rc = mdb_update_key(csrc->mc_pg[csrc->mc_top-1], 0, &key)) != MDB_SUCCESS)
			return rc;
	}

	mdb_midl_append(csrc->mc_txn->mt_free_pgs, csrc->mc_pg[csrc->mc_top]->mp_pgno);
	if (IS_LEAF(csrc->mc_pg[csrc->mc_top]))
		csrc->mc_txn->mt_dbs[csrc->mc_dbi].md_leaf_pages--;
	else
		csrc->mc_txn->mt_dbs[csrc->mc_dbi].md_branch_pages--;
	cursor_pop_page(csrc);

	return mdb_rebalance(csrc);
}

static void
mdb_cursor_copy(const MDB_cursor *csrc, MDB_cursor *cdst)
{
	unsigned int i;

	cdst->mc_txn = csrc->mc_txn;
	cdst->mc_dbi = csrc->mc_dbi;
	cdst->mc_snum = csrc->mc_snum;
	cdst->mc_top = csrc->mc_top;
	cdst->mc_flags = csrc->mc_flags;

	for (i=0; i<csrc->mc_snum; i++) {
		cdst->mc_pg[i] = csrc->mc_pg[i];
		cdst->mc_ki[i] = csrc->mc_ki[i];
	}
}

static int
mdb_rebalance(MDB_cursor *mc)
{
	MDB_node	*node;
	MDB_page	*root;
	int rc;
	unsigned int ptop;
	MDB_cursor	mn;

	DPRINTF("rebalancing %s page %lu (has %u keys, %.1f%% full)",
	    IS_LEAF(mc->mc_pg[mc->mc_top]) ? "leaf" : "branch",
	    mc->mc_pg[mc->mc_top]->mp_pgno, NUMKEYS(mc->mc_pg[mc->mc_top]), (float)PAGEFILL(mc->mc_txn->mt_env, mc->mc_pg[mc->mc_top]) / 10);

	if (PAGEFILL(mc->mc_txn->mt_env, mc->mc_pg[mc->mc_top]) >= FILL_THRESHOLD) {
		DPRINTF("no need to rebalance page %lu, above fill threshold",
		    mc->mc_pg[mc->mc_top]->mp_pgno);
		return MDB_SUCCESS;
	}

	if (mc->mc_snum < 2) {
		if (NUMKEYS(mc->mc_pg[mc->mc_top]) == 0) {
			DPUTS("tree is completely empty");
			mc->mc_txn->mt_dbs[mc->mc_dbi].md_root = P_INVALID;
			mc->mc_txn->mt_dbs[mc->mc_dbi].md_depth = 0;
			mc->mc_txn->mt_dbs[mc->mc_dbi].md_leaf_pages = 0;
			mdb_midl_append(mc->mc_txn->mt_free_pgs, mc->mc_pg[mc->mc_top]->mp_pgno);
		} else if (IS_BRANCH(mc->mc_pg[mc->mc_top]) && NUMKEYS(mc->mc_pg[mc->mc_top]) == 1) {
			DPUTS("collapsing root page!");
			mdb_midl_append(mc->mc_txn->mt_free_pgs, mc->mc_pg[mc->mc_top]->mp_pgno);
			mc->mc_txn->mt_dbs[mc->mc_dbi].md_root = NODEPGNO(NODEPTR(mc->mc_pg[mc->mc_top], 0));
			if ((rc = mdb_get_page(mc->mc_txn, mc->mc_txn->mt_dbs[mc->mc_dbi].md_root, &root)))
				return rc;
			mc->mc_txn->mt_dbs[mc->mc_dbi].md_depth--;
			mc->mc_txn->mt_dbs[mc->mc_dbi].md_branch_pages--;
		} else
			DPUTS("root page doesn't need rebalancing");
		return MDB_SUCCESS;
	}

	/* The parent (branch page) must have at least 2 pointers,
	 * otherwise the tree is invalid.
	 */
	ptop = mc->mc_top-1;
	assert(NUMKEYS(mc->mc_pg[ptop]) > 1);

	/* Leaf page fill factor is below the threshold.
	 * Try to move keys from left or right neighbor, or
	 * merge with a neighbor page.
	 */

	/* Find neighbors.
	 */
	mdb_cursor_copy(mc, &mn);
	mn.mc_xcursor = NULL;

	if (mc->mc_ki[ptop] == 0) {
		/* We're the leftmost leaf in our parent.
		 */
		DPUTS("reading right neighbor");
		mn.mc_ki[ptop]++;
		node = NODEPTR(mc->mc_pg[ptop], mn.mc_ki[ptop]);
		if ((rc = mdb_get_page(mc->mc_txn, NODEPGNO(node), &mn.mc_pg[mn.mc_top])))
			return rc;
		mn.mc_ki[mn.mc_top] = 0;
		mc->mc_ki[mc->mc_top] = NUMKEYS(mc->mc_pg[mc->mc_top]);
	} else {
		/* There is at least one neighbor to the left.
		 */
		DPUTS("reading left neighbor");
		mn.mc_ki[ptop]--;
		node = NODEPTR(mc->mc_pg[ptop], mn.mc_ki[ptop]);
		if ((rc = mdb_get_page(mc->mc_txn, NODEPGNO(node), &mn.mc_pg[mn.mc_top])))
			return rc;
		mn.mc_ki[mn.mc_top] = NUMKEYS(mn.mc_pg[mn.mc_top]) - 1;
		mc->mc_ki[mc->mc_top] = 0;
	}

	DPRINTF("found neighbor page %lu (%u keys, %.1f%% full)",
	    mn.mc_pg[mn.mc_top]->mp_pgno, NUMKEYS(mn.mc_pg[mn.mc_top]), (float)PAGEFILL(mc->mc_txn->mt_env, mn.mc_pg[mn.mc_top]) / 10);

	/* If the neighbor page is above threshold and has at least two
	 * keys, move one key from it.
	 *
	 * Otherwise we should try to merge them.
	 */
	if (PAGEFILL(mc->mc_txn->mt_env, mn.mc_pg[mn.mc_top]) >= FILL_THRESHOLD && NUMKEYS(mn.mc_pg[mn.mc_top]) >= 2)
		return mdb_move_node(&mn, mc);
	else { /* FIXME: if (has_enough_room()) */
		if (mc->mc_ki[ptop] == 0)
			return mdb_merge(&mn, mc);
		else
			return mdb_merge(mc, &mn);
	}
}

static int
mdb_del0(MDB_cursor *mc, MDB_node *leaf)
{
	int rc;

	/* add overflow pages to free list */
	if (!IS_LEAF2(mc->mc_pg[mc->mc_top]) && F_ISSET(leaf->mn_flags, F_BIGDATA)) {
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
	mdb_del_node(mc->mc_pg[mc->mc_top], mc->mc_ki[mc->mc_top], mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad);
	mc->mc_txn->mt_dbs[mc->mc_dbi].md_entries--;
	rc = mdb_rebalance(mc);
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

/* Split page <mc->top>, and insert <key,(data|newpgno)> in either left or
 * right sibling, at index <mc->ki> (as if unsplit). Updates mc->top and
 * mc->ki with the actual values after split, ie if mc->top and mc->ki
 * refer to a node in the new right sibling page.
 */
static int
mdb_split(MDB_cursor *mc, MDB_val *newkey, MDB_val *newdata, pgno_t newpgno)
{
	uint8_t		 flags;
	int		 rc = MDB_SUCCESS, ins_new = 0;
	indx_t		 newindx;
	pgno_t		 pgno = 0;
	unsigned int	 i, j, split_indx, nkeys, pmax;
	MDB_node	*node;
	MDB_val	 sepkey, rkey, rdata;
	MDB_page	*copy;
	MDB_page	*mp, *rp, *pp;
	unsigned int ptop;
	MDB_cursor	mn;
	DKBUF;

	mp = mc->mc_pg[mc->mc_top];
	newindx = mc->mc_ki[mc->mc_top];

	DPRINTF("-----> splitting %s page %lu and adding [%s] at index %i",
	    IS_LEAF(mp) ? "leaf" : "branch", mp->mp_pgno,
	    DKEY(newkey), mc->mc_ki[mc->mc_top]);

	if (mc->mc_snum < 2) {
		if ((pp = mdb_new_page(mc, P_BRANCH, 1)) == NULL)
			return ENOMEM;
		/* shift current top to make room for new parent */
		mc->mc_pg[1] = mc->mc_pg[0];
		mc->mc_ki[1] = mc->mc_ki[0];
		mc->mc_pg[0] = pp;
		mc->mc_ki[0] = 0;
		mc->mc_txn->mt_dbs[mc->mc_dbi].md_root = pp->mp_pgno;
		DPRINTF("root split! new root = %lu", pp->mp_pgno);
		mc->mc_txn->mt_dbs[mc->mc_dbi].md_depth++;

		/* Add left (implicit) pointer. */
		if ((rc = mdb_add_node(mc, 0, NULL, NULL, mp->mp_pgno, 0)) != MDB_SUCCESS) {
			/* undo the pre-push */
			mc->mc_pg[0] = mc->mc_pg[1];
			mc->mc_ki[0] = mc->mc_ki[1];
			mc->mc_txn->mt_dbs[mc->mc_dbi].md_root = mp->mp_pgno;
			mc->mc_txn->mt_dbs[mc->mc_dbi].md_depth--;
			return rc;
		}
		mc->mc_snum = 2;
		mc->mc_top = 1;
		ptop = 0;
	} else {
		ptop = mc->mc_top-1;
		DPRINTF("parent branch page is %lu", mc->mc_pg[ptop]->mp_pgno);
	}

	/* Create a right sibling. */
	if ((rp = mdb_new_page(mc, mp->mp_flags, 1)) == NULL)
		return ENOMEM;
	mdb_cursor_copy(mc, &mn);
	mn.mc_pg[mn.mc_top] = rp;
	mn.mc_ki[ptop] = mc->mc_ki[ptop]+1;
	DPRINTF("new right sibling: page %lu", rp->mp_pgno);

	nkeys = NUMKEYS(mp);
	split_indx = nkeys / 2 + 1;

	if (IS_LEAF2(rp)) {
		char *split, *ins;
		int x;
		unsigned int lsize, rsize, ksize;
		/* Move half of the keys to the right sibling */
		copy = NULL;
		x = mc->mc_ki[mc->mc_top] - split_indx;
		ksize = mc->mc_txn->mt_dbs[mc->mc_dbi].md_pad;
		split = LEAF2KEY(mp, split_indx, ksize);
		rsize = (nkeys - split_indx) * ksize;
		lsize = (nkeys - split_indx) * sizeof(indx_t);
		mp->mp_lower -= lsize;
		rp->mp_lower += lsize;
		mp->mp_upper += rsize - lsize;
		rp->mp_upper -= rsize - lsize;
		sepkey.mv_size = ksize;
		if (newindx == split_indx) {
			sepkey.mv_data = newkey->mv_data;
		} else {
			sepkey.mv_data = split;
		}
		if (x<0) {
			ins = LEAF2KEY(mp, mc->mc_ki[mc->mc_top], ksize);
			memcpy(rp->mp_ptrs, split, rsize);
			sepkey.mv_data = rp->mp_ptrs;
			memmove(ins+ksize, ins, (split_indx - mc->mc_ki[mc->mc_top]) * ksize);
			memcpy(ins, newkey->mv_data, ksize);
			mp->mp_lower += sizeof(indx_t);
			mp->mp_upper -= ksize - sizeof(indx_t);
		} else {
			if (x)
				memcpy(rp->mp_ptrs, split, x * ksize);
			ins = LEAF2KEY(rp, x, ksize);
			memcpy(ins, newkey->mv_data, ksize);
			memcpy(ins+ksize, split + x * ksize, rsize - x * ksize);
			rp->mp_lower += sizeof(indx_t);
			rp->mp_upper -= ksize - sizeof(indx_t);
			mc->mc_ki[mc->mc_top] = x;
			mc->mc_pg[mc->mc_top] = rp;
		}
		goto newsep;
	}

	/* For leaf pages, check the split point based on what
	 * fits where, since otherwise add_node can fail.
	 */
	if (IS_LEAF(mp)) {
		unsigned int psize, nsize;
		/* Maximum free space in an empty page */
		pmax = mc->mc_txn->mt_env->me_psize - PAGEHDRSZ;
		nsize = mdb_leaf_size(mc->mc_txn->mt_env, newkey, newdata);
		if (newindx < split_indx) {
			psize = nsize;
			for (i=0; i<split_indx; i++) {
				node = NODEPTR(mp, i);
				psize += NODESIZE + NODEKSZ(node) + sizeof(indx_t);
				if (F_ISSET(node->mn_flags, F_BIGDATA))
					psize += sizeof(pgno_t);
				else
					psize += NODEDSZ(node);
				psize += psize & 1;
				if (psize > pmax) {
					split_indx = i;
					break;
				}
			}
		} else {
			psize = nsize;
			for (i=nkeys-1; i>=split_indx; i--) {
				node = NODEPTR(mp, i);
				psize += NODESIZE + NODEKSZ(node) + sizeof(indx_t);
				if (F_ISSET(node->mn_flags, F_BIGDATA))
					psize += sizeof(pgno_t);
				else
					psize += NODEDSZ(node);
				psize += psize & 1;
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
		node = NODEPTR(mp, split_indx);
		sepkey.mv_size = node->mn_ksize;
		sepkey.mv_data = NODEKEY(node);
	}

newsep:
	DPRINTF("separator is [%s]", DKEY(&sepkey));

	/* Copy separator key to the parent.
	 */
	if (SIZELEFT(mn.mc_pg[ptop]) < mdb_branch_size(mc->mc_txn->mt_env, &sepkey)) {
		mn.mc_snum--;
		mn.mc_top--;
		rc = mdb_split(&mn, &sepkey, NULL, rp->mp_pgno);

		/* Right page might now have changed parent.
		 * Check if left page also changed parent.
		 */
		if (mn.mc_pg[ptop] != mc->mc_pg[ptop] &&
		    mc->mc_ki[ptop] >= NUMKEYS(mc->mc_pg[ptop])) {
			mc->mc_pg[ptop] = mn.mc_pg[ptop];
			mc->mc_ki[ptop] = mn.mc_ki[ptop] - 1;
		}
	} else {
		mn.mc_top--;
		rc = mdb_add_node(&mn, mn.mc_ki[ptop], &sepkey, NULL, rp->mp_pgno, 0);
		mn.mc_top++;
	}
	if (IS_LEAF2(rp)) {
		return rc;
	}
	if (rc != MDB_SUCCESS) {
		return rc;
	}

	/* Move half of the keys to the right sibling. */

	/* grab a page to hold a temporary copy */
	if (mc->mc_txn->mt_env->me_dpages) {
		copy = mc->mc_txn->mt_env->me_dpages;
		mc->mc_txn->mt_env->me_dpages = copy->mp_next;
	} else {
		if ((copy = malloc(mc->mc_txn->mt_env->me_psize)) == NULL)
			return ENOMEM;
	}

	copy->mp_pgno  = mp->mp_pgno;
	copy->mp_flags = mp->mp_flags;
	copy->mp_lower = PAGEHDRSZ;
	copy->mp_upper = mc->mc_txn->mt_env->me_psize;
	mc->mc_pg[mc->mc_top] = copy;
	for (i = j = 0; i <= nkeys; j++) {
		if (i == split_indx) {
		/* Insert in right sibling. */
		/* Reset insert index for right sibling. */
			j = (i == newindx && ins_new);
			mc->mc_pg[mc->mc_top] = rp;
		}

		if (i == newindx && !ins_new) {
			/* Insert the original entry that caused the split. */
			rkey.mv_data = newkey->mv_data;
			rkey.mv_size = newkey->mv_size;
			if (IS_LEAF(mp)) {
				rdata.mv_data = newdata->mv_data;
				rdata.mv_size = newdata->mv_size;
			} else
				pgno = newpgno;
			flags = 0;

			ins_new = 1;

			/* Update page and index for the new key. */
			mc->mc_ki[mc->mc_top] = j;
		} else if (i == nkeys) {
			break;
		} else {
			node = NODEPTR(mp, i);
			rkey.mv_data = NODEKEY(node);
			rkey.mv_size = node->mn_ksize;
			if (IS_LEAF(mp)) {
				rdata.mv_data = NODEDATA(node);
				rdata.mv_size = NODEDSZ(node);
			} else
				pgno = NODEPGNO(node);
			flags = node->mn_flags;

			i++;
		}

		if (!IS_LEAF(mp) && j == 0) {
			/* First branch index doesn't need key data. */
			rkey.mv_size = 0;
		}

		rc = mdb_add_node(mc, j, &rkey, &rdata, pgno, flags);
	}

	/* reset back to original page */
	if (newindx < split_indx)
		mc->mc_pg[mc->mc_top] = mp;

	nkeys = NUMKEYS(copy);
	for (i=0; i<nkeys; i++)
		mp->mp_ptrs[i] = copy->mp_ptrs[i];
	mp->mp_lower = copy->mp_lower;
	mp->mp_upper = copy->mp_upper;
	memcpy(NODEPTR(mp, nkeys-1), NODEPTR(copy, nkeys-1),
		mc->mc_txn->mt_env->me_psize - copy->mp_upper);

	/* return tmp page to freelist */
	copy->mp_next = mc->mc_txn->mt_env->me_dpages;
	mc->mc_txn->mt_env->me_dpages = copy;
	return rc;
}

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
	/** Only a subset of the @ref mdb_env flags can be changed
	 *	at runtime. Changing other flags requires closing the environment
	 *	and re-opening it with the new flags.
	 */
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
	if (txn->mt_dbs[dbi].md_flags & MDB_REVERSEKEY)
		txn->mt_dbxs[dbi].md_cmp = memnrcmp;
	else if (txn->mt_dbs[dbi].md_flags & MDB_INTEGERKEY)
		txn->mt_dbxs[dbi].md_cmp = cintcmp;
	else
		txn->mt_dbxs[dbi].md_cmp = memncmp;

	if (txn->mt_dbs[dbi].md_flags & MDB_DUPSORT) {
		if (txn->mt_dbs[dbi].md_flags & MDB_INTEGERDUP) {
			if (txn->mt_dbs[dbi].md_flags & MDB_DUPFIXED)
				txn->mt_dbxs[dbi].md_dcmp = intcmp;
			else
				txn->mt_dbxs[dbi].md_dcmp = cintcmp;
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
