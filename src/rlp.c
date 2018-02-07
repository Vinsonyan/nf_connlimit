/* Kernel module to addrange parameters. */

/* (C) 2013 LeadSec
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>

#include "class_core.h"
#include "addr_group.h"

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "LeadSec" );
MODULE_DESCRIPTION( "rlp for addr group object kernel module" );
#ifdef ADDR_GROUP_RLP

static inline u32
rlp_maxkey(u8 bittype)
{
	if (bittype == BIT_U16)
		return U16_MAX;
	return U32_MAX;
}

static inline int
u16_key_exists(const struct rlp_spec *spec, u32 key, struct locate_inf *inf,
                u32 *position)
{
	return 0;
}

static inline int
u32_key_exists(const struct rlp_spec *spec, u32 key, struct locate_inf *inf,
		u32 *position)
{
	const u32 *part = FIRST_KEY(spec);
	u32 left = 0;
	u32 right = spec->num - 1;
	u32 pos;

	while (left <= right) {
		pos = (left + right) >> 1;
		if (part[pos] < key) {
			left = pos + 1;
		} else if (pos && part[pos - 1] >= key) {
			right = pos - 1;
		} else {
			if (inf != NULL) {
				inf->key = part[pos];
				inf->nextspec = FIRST_NEXTSPEC(spec) +
					pos * sizeof(void *);
			}
			if (position != NULL) 
				*position = pos;

			return part[pos] == key;
		}
	}

	/* should never be reached */
	ASSERT(1 == 0);

	return 0;
}

rlp_error
rlp_locate(const struct rlp_spec *spec, struct locate_inf *inf, u32 key)
{
	if (spec == NULL || inf == NULL) {
		ARG_ERR;
		return RLP_ERR;
	}

	switch (spec->bittype) {
	case BIT_U16:
		u16_key_exists(spec, key, inf, NULL);
		break;
	case 1:
		u32_key_exists(spec, key, inf, NULL);
		break;
	default:
		return RLP_ERR;
	}
	return RLP_OK;
}
EXPORT_SYMBOL_GPL( rlp_locate );

struct rlp_spec *
rlp_new(u8 bittype, u8 ins_num, const u32 key[],
	struct gen_spec *nextspec[])
{
	struct rlp_spec *new_rlp;
	unsigned int rlp_size;

	if (unlikely(bittype > BIT_U32 || key == NULL || nextspec == NULL ||
		     !(ins_num == 1 || ins_num == 2) ||
		     (ins_num == 1 && key[0] != rlp_maxkey(bittype)) ||
		     (ins_num == 2 && (key[0] >= key[1] ||
				       key[1] != rlp_maxkey(bittype))))) {
		ARG_ERR;
		return NULL;
	}

	rlp_size = sizeof(*new_rlp) + IPT_ALIGN(ins_num * KEYSIZE(bittype)) +
		   ins_num * sizeof(void *);

	new_rlp = (struct rlp_spec *)netobj_kzalloc(rlp_size, GFP_ATOMIC);
			   
	if (new_rlp == NULL) {
		return NULL;
	}
	
	new_rlp->rlp = 1;
	new_rlp->bittype = bittype;
	new_rlp->num = ins_num;
	new_rlp->size = rlp_size;

	switch (bittype) {
	case BIT_U16: 
		break;

	case BIT_U32:{ 
		u32 *k = FIRST_KEY(new_rlp);
		struct gen_spec **s = FIRST_NEXTSPEC(new_rlp);
		k[0] = key[0];
		s[0] = nextspec[0];
		if (ins_num == 2) {
			k[1] = key[1];
			s[1] = nextspec[1];
		}
		break;
	}
	}
	return new_rlp;
}

rlp_error
rlp_insert(const struct rlp_spec *spec, u8 ins_num, const u32 key[],
	   struct gen_spec *nextspec[], struct rlp_spec **result)
{
	void *first_ksrc, *ksrc, *kdst, *nsrc, *ndst;
	struct gen_spec *lnspec[2];
	u32 pos[2], lkey[2];
	u32 i, ksize, nsize;
	unsigned int newrlp_size;

	if (unlikely(spec == NULL || key == NULL || nextspec == NULL ||
		     result == NULL || !(ins_num == 1 || ins_num == 2) ||
		     (ins_num == 1 &&
		      key[0] >= rlp_maxkey(spec->bittype)) ||
		     (ins_num == 2 &&
		      (key[0] >= key[1] ||
		       key[1] >= rlp_maxkey(spec->bittype))))) {
		ARG_ERR;
		return RLP_ERR;
	}

	switch (spec->bittype) {
	case BIT_U16: {
		break;
	}
	case BIT_U32: {
		u8 ct = 0;
		if (!u32_key_exists(spec, key[0], NULL, &pos[0])) {
			lkey[ct] = key[0];
			lnspec[ct++] = nextspec[0];
		}
		if (ins_num == 2 &&
		    !u32_key_exists(spec, key[1], NULL, &pos[ct])) {
			ASSERT(ct == 0 || pos[0] <= pos[1]);
			lkey[ct] = key[1];
			lnspec[ct++] = nextspec[1];
		}
		ASSERT(ins_num == ct);
		ins_num = ct;
		break;
	}
	}

	/* ins_num can be 0, 1 or 2 here */
	ASSERT(ins_num == 1 || ins_num == 2);
	newrlp_size = sizeof(**result) +
		IPT_ALIGN((spec->num+ins_num) * KEYSIZE(spec->bittype)) +
		(spec->num + ins_num) * sizeof(void *);

	*result = (struct rlp_spec*)netobj_kzalloc(newrlp_size, GFP_ATOMIC);

	if (*result == NULL)
		return RLP_ERR;

	memcpy(*result, spec, sizeof(*spec));
	(*result)->num += ins_num;
	(*result)->size = newrlp_size;

	first_ksrc = FIRST_KEY(spec);
	ksrc = first_ksrc;
	kdst = FIRST_KEY(*result);
	nsrc = FIRST_NEXTSPEC(spec);
	ndst = FIRST_NEXTSPEC(*result);
	for (i = 0; i < ins_num; i++) {
		ksize = (first_ksrc + pos[i] * KEYSIZE(spec->bittype)) - ksrc;	/* p1 to kp size */
		nsize = (ksize / KEYSIZE(spec->bittype)) * sizeof(void *);	/* p1 to kp number * sizeof(void*) */
		if (ksize > 0) {
			memcpy(kdst, ksrc, ksize);
			memcpy(ndst, nsrc, nsize);
		}
		ksrc += ksize;
		kdst += ksize;
		nsrc += nsize;
		ndst += nsize;
		switch (spec->bittype) {
		case BIT_U16:
			break;
		case BIT_U32:
			*(u32 *) kdst = lkey[i];
			break;
		}
		*(struct gen_spec **) ndst = lnspec[i];
		kdst += KEYSIZE(spec->bittype);
		ndst += sizeof(void *);
	}
	ksize = (spec->num - (ins_num == 0 ? 0 : pos[ins_num - 1])) *
		KEYSIZE(spec->bittype);
	ASSERT(ksize > 0);
	nsize = (ksize / KEYSIZE(spec->bittype)) * sizeof(void *);
	memcpy(kdst, ksrc, ksize);
	memcpy(ndst, nsrc, nsize);

	return RLP_OK;
}

#if 0
static void
rlp_printf( struct rlp_spec *spec )
{
	rlp_error stat;
	u32 key = 0;
	struct locate_inf inf;
duprintf( KERN_ERR, "0x%p###############################################\n", spec );
	do {
		stat = rlp_locate(spec, &inf, key);
		if ( RLP_ERR == stat ) 
			return ;
		
		duprintf( KERN_ERR, "DEBUG: key is[0x%x], ", inf.key );
		if ( *inf.nextspec == g_gen_spec )
			duprintf(KERN_ERR, "miss!!\n" );
		else
			duprintf( KERN_ERR,"No miss!\n" );
		key = inf.key +1;

	} while ( inf.key < MAXKEY(BIT_U32) );

duprintf( KERN_ERR, "0x%p###############################################\n", spec );
	return ;
}

#endif

static rlp_error
segment_insert(struct rlp_spec **spec, u32 left, u32 right)
{  	
	u8 ins_num = 0;
	struct gen_spec* new_nextspec[2] = {NULL, NULL};
	struct locate_inf inf;
	u32 new_key[2];
	rlp_error stat;

	if (left > 0) {
		stat = rlp_locate(*spec, &inf, left - 1);
		if (stat != RLP_OK) {
			goto error;
		}
		if (inf.key != left - 1) {
			new_key[ins_num] = left - 1;
			new_nextspec[ins_num] = *(inf.nextspec);
			ins_num++;
		}
	}

	stat = rlp_locate(*spec, &inf, right);
	if (stat != RLP_OK) {
		goto error;
	}

	if (inf.key != right) {
		new_key[ins_num] = right;
		ins_num++;
	}

	if (ins_num > 0) {
		struct rlp_spec *b;
		ASSERT(ins_num == 1 || new_key[0] != new_key[1]);
		stat = rlp_insert(*spec, ins_num, new_key, new_nextspec, &b);
		if (stat != RLP_OK) {
			goto error;
		}
		netobj_kfree( *spec, (*spec)->size );
		*spec = b;

	} else {
		/* same left-right nothing */
	}

	return RLP_OK;

error:
	return RLP_ERR;
}

rlp_error
addr_group_rlp_insert( struct rlp_spec **spec, u_int32_t ip, u_int32_t ip2, u8 family )
{
	struct locate_inf inf;
	rlp_error stat;
	u_int32_t left = ntohl(ip);
	u_int32_t right = ntohl(ip2);
#ifdef DEBUG
	//rlp_printf( *spec );
#endif
	stat = segment_insert(spec, left, right);
	if (stat != RLP_OK)
		return stat;
	do {
		stat = rlp_locate(*spec, &inf, left);
		if (stat != RLP_OK) {
			return stat;
		}
		left  = inf.key + 1;

		*inf.nextspec = g_gen_spec;
		if (stat != RLP_OK) {
			return stat;
		}
	} while (inf.key < right);

	return RLP_OK;	
}
EXPORT_SYMBOL_GPL(addr_group_rlp_insert);

/* Find key from rlp tree */
int addr_group_rlp_find( struct rlp_spec *spec, const u_int32_t key  )
{
	rlp_error stat;
	int ret = 1;
	struct locate_inf inf;

	if ( spec == NULL )
		return -1;

#ifdef DEBUG
	//rlp_printf( spec );
#endif

	stat = rlp_locate( spec, &inf, ntohl(key)) ;	
	if ( RLP_ERR == stat )
		return -1;

	if ( *inf.nextspec != g_gen_spec ) 
		return 0;

	return ret;
}
EXPORT_SYMBOL_GPL(addr_group_rlp_find);

rlp_error addr_group_rlp_init( struct rlp_spec **spec, u8 family )
{
	u8 bittype = family;
	struct gen_spec *nextspec[] = {NULL};
	u32 key = MAXKEY(bittype);

	*spec = rlp_new(bittype, 1, &key, nextspec);
	if (spec == NULL) {
		return RLP_ERR;
	}

	return RLP_OK;
}
EXPORT_SYMBOL_GPL(addr_group_rlp_init);

#endif	/* ADDR_GROUP_RLP */
