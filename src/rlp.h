#ifndef __RLP_H__
#define __RLP_H__

#include <linux/slab.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include "class_core.h"

#define ARG_ERR	BUG_PRINT("function arguments invalid\n")

#define U16_MAX	0xffff
#define U32_MAX 0xffffffff
#define U128_MAX	0xffffffffffffffffffffffffffffffff

#define BIT_U16		0
#define BIT_U32		1

#define MAXKEY(bittype) \
((bittype) == BIT_U16 ? U16_MAX : U32_MAX)

#define KEYSIZE(bittype) (1 << ((bittype) + 1))
#define FIRST_KEY(spec)     ((void *) (spec) + sizeof(*(spec)))
#define FIRST_NEXTSPEC(spec) (FIRST_KEY(spec) +                              \
		IPT_ALIGN((spec)->num * KEYSIZE((spec)->bittype)))


typedef enum {
	RLP_OK	=  0,
	RLP_ERR	= -1
} rlp_error;

typedef struct gen_spec {
	unsigned rlp : 1; 

} addr_group_rlp_t;

struct locate_inf {
	u32 key;
	struct gen_spec **nextspec;
};

/* rlp header */
struct rlp_spec {
	unsigned rlp       :  1; 
	unsigned bittype   :  1; // {BIT_U16, BIT_U32}
	unsigned num       : 24; // number of elements in the rlp
	unsigned int size;

	struct gen_spec * (*locate)(const struct rlp_spec *spec,
			void *packet);
};

/* Export rlp api */
extern rlp_error addr_group_rlp_init( struct rlp_spec **spec, u8 family );
extern rlp_error addr_group_rlp_insert( struct rlp_spec **spec, u_int32_t ip, u_int32_t ip2, u8 family );
extern int addr_group_rlp_find( struct rlp_spec *spec, const u_int32_t key  );
extern rlp_error rlp_locate(const struct rlp_spec *spec, struct locate_inf *inf, u32 key);
#endif	/* __RLP_H__ */
