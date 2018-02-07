#ifndef __CLASS_CORE_H__
#define __CLASS_CORE_H__

#include <linux/types.h>

#ifndef NETOBJ_METHOD
#define NETOBJ_METHOD
#endif

#define MAX_CLASS_NAME_LEN	32
#define MAX_OBJ_NAME_LEN	((32 * 3) + 1)

#ifdef __KERNEL__
#ifdef DEBUG
#define ASSERT(x)  							\
do {									\
	if (!(x)) {							\
		printk(KERN_EMERG "assertion failed %s: %d: %s\n",	\
		       __FILE__, __LINE__, #x);				\
		BUG();							\
	}								\
} while (0)
#else	/* DEBUG */
#define ASSERT(x) do { } while (0)
#endif	/* DEBUG END */

#define MODULE_NAME	"netobj"
#define NETOBJ_PROC_PATH	"/proc/sys/leadsec/netobj"

#endif	/* __KERNEL__ */

enum netobj_sockopt_method {
	NETOBJ_SOCKOPT_METHOD_GET,
	NETOBJ_SOCKOPT_METHOD_SET,
};

#define NET_OBJECT_BASE     2048
enum netobj_so_set_cmds {
	/* L3_addr group */
	ADDR_GROUP_OBJ_ADD = NET_OBJECT_BASE,
	ADDR_GROUP_OBJ_DELETE,
	ADDR_GROUP_OBJ_MODIFY,
	ADDR_GROUP_OBJ_FLUSH,

	/* Service object */	
	SERVICE_OBJ_ADD,
        SERVICE_OBJ_MODIFY,
        SERVICE_OBJ_DELETE,
        SERVICE_OBJ_EMPTY,	

	/* Service group */
	SERV_GROUP_OBJ_ADD,
	SERV_GROUP_OBJ_MODIFY,
	SERV_GROUP_OBJ_DELETE,
	SERV_GROUP_OBJ_EMPTY,
	SERV_GROUP_OBJ_SET_MAX,

	/* Seczone object */
	SECZONE_OBJ_SZ_ADD,
	SECZONE_OBJ_SZ_RENAME,
	SECZONE_OBJ_SZ_SET,
	SECZONE_OBJ_SZ_DEL,
	
	/* Time object */
	TIMEOBJ_OBJ_ADD,
	TIMEOBJ_OBJ_SET,
	TIMEOBJ_OBJ_DEL,
	
	/* Timegrp object */
	TIMEGRP_OBJ_ADD,
	TIMEGRP_OBJ_SET,
	TIMEGRP_OBJ_DEL,

	/* connlimit object */
	CONNLIMIT_OBJ_ADD,
	CONNLIMIT_OBJ_MODIFY,
	CONNLIMIT_OBJ_DELETE,

	NET_OBJECT_SET_MAX,
};

enum netobj_so_get_cmds {
	/* L3_addr group */
	ADDR_GROUP_OBJ_EXIST = NET_OBJECT_BASE,
	ADDR_GROUP_OBJ_GET_COUNT,
	ADDR_GROUP_OBJ_SHOW,

	/* Service object */
	SERVICE_OBJ_SHOW,
	SERVICE_OBJ_EXIST,
	SERVICE_OBJ_COUNT,

	/* Service group */
	SERV_GROUP_OBJ_SHOW,
	SERV_GROUP_OBJ_EXIST,
	SERV_GROUP_OBJ_COUNT,
	SERV_GROUP_OBJ_GET_MAX,

	/* Seczone object */
	SECZONE_OBJ_GET_REFCNT_INF,
	SECZONE_OBJ_GET_REFCNT,

	/* Time object */
	TIMEOBJ_OBJ_GET_REFCNT_INF,
	TIMEOBJ_OBJ_GET_REFCNT,

	/* Timegrp object */
	TIMEGRP_OBJ_GET_REFCNT_INF,
	TIMEGRP_OBJ_GET_REFCNT,

	/* connlimit object */
	CONNLIMIT_OBJ_SHOW,
	CONNLIMIT_OBJ_EXIST,

	NET_OBJECT_GET_MAX,
};

#ifdef __KERNEL__
typedef struct class_item_cfg {
	/* Maximum limit */
	u32 max_size;
	atomic_t cur_size;

	/* Maximum number of group */
	u32 max_number;
	atomic_t cur_number;

} class_cfg_t;

typedef int  (* sockopt_func)(void __user *user, int *len);
typedef struct sockopt_array_s
{
	u32 id;
	u32	method;	
	sockopt_func sockopt_proc;
} sockopt_array;

/* Class item struct */
typedef struct class_item {
	struct list_head list;
	const char class_name[MAX_CLASS_NAME_LEN];
	
	/* Func for operation class_item */
	void( *bind_class )( struct class_item * );
	void( *release_class)( struct class_item * );

	/* Func for operaton netobj */
	unsigned long ( *find_bind_object )( const char *obj_name );	
	unsigned long ( *find_object )( const char *obj_name, unsigned char flags );
	//void( *bind_object )( unsigned long obj_addr );
	void( *release_object )( unsigned long obj_addr );

	/* Func for iptables match */
	int ( *do_stuff )( unsigned long obj_addr, int cmd, void *info, int *len );	
	
	/* refcnt */
	atomic_t refcnt;

	/* Master class and child class */
	struct class_item *master;
	struct class_item *child;

	/* Configure */
	class_cfg_t cfg;

	/* Sockopt function */
//#ifdef NETOBJ_METHOD
	sockopt_array *sockopts;
//#endif
	/* Module */
	struct module *owner;

}class_item_t ;

typedef struct ipt_class_info{
	char class_name[MAX_CLASS_NAME_LEN];
	char obj_name[MAX_OBJ_NAME_LEN];
	unsigned char flags;

	/* Used internally by the kernel  */
	class_item_t *class_ptr;
	unsigned long obj_addr;
	
} class_match_t;

/* Class type */
enum {
	MATCH_PKT_SERVICE	 = 0,
	MATCH_PKT_SERVGRP,
	MATCH_PKT_SRCRANGE,
	MATCH_PKT_IPV4,
	MATCH_PKT_IPV6,
	MATCH_PKT_MAX,
};

/* Memory information statistics */
typedef struct class_mem_info {
	char memory_info[1024];
	size_t total_alloc_size;
	size_t total_alloc_realsize;
	size_t getpages_size;
	size_t getpages_realsize;
	u32 getpages_number;
	size_t vmalloc_size;
	size_t vmalloc_realsize;
	u32 vmalloc_number;
	atomic_t refcnt;
	size_t mem_max_size;
	
} mem_info_t;

#ifndef _HIPAC_GLOBAL_H

static inline unsigned int
kmalloc_size( size_t size )
{
        unsigned int s;
#define CACHE( x ) if ( size <= x ) { s = x; goto found;}
#include <linux/kmalloc_sizes.h>
        return 0;
found:
        return s;
}

static inline unsigned int
getpages_size( size_t size )
{
        return size == 0 ? 0 : ( PAGE_SIZE << get_order(size) );
}
#endif/*_HIPAC_GLOBAL_H*/

/* Export API */
extern class_cfg_t cfg;

#ifdef CONFIG_PROC_FS
extern struct proc_dir_entry *proc_netobj;
#endif
extern int register_class_item( class_item_t *me );
extern void unregister_class_item( class_item_t *me );
extern int netobj_sockopts_register( sockopt_array *sockopts ); 
extern void netobj_sockopts_unregister(sockopt_array *sockopts);
extern class_item_t *find_class_item( const char *class_name );
extern void bind_class_item( class_item_t *me );
extern void release_class_item( class_item_t *me );
extern int ipt_class_checkentry( void *matchinfo );
extern void ipt_class_destroy( void *matchinfo );
extern void * netobj_kmalloc( size_t size, gfp_t flags );
extern void * netobj_kzalloc( size_t size, gfp_t flags );
extern void netobj_kfree( const void *p, size_t size );

extern struct mutex class_lock;

#endif	/* __KERNEL__ */

#endif	/* __CLASS_CORE_H__ */
