#ifndef __NETNS_CONNTRACK_H
#define __NETNS_CONNTRACK_H

#include <linux/list.h>
#include <linux/list_nulls.h>
#include <asm/atomic.h>

struct ctl_table_header;
struct nf_conntrack_ecache;

/* 该结构主要用于linux的网络命名空间，表示nf_conntrack在不同的命名空间中都有一套独立的数据信息 */
struct netns_ct {
	atomic_t		count;
	unsigned int		expect_count;
	unsigned int		htable_size;
	struct kmem_cache	*nf_conntrack_cachep;
	struct hlist_nulls_head	*hash;
	struct hlist_head	*expect_hash;
	struct hlist_nulls_head	unconfirmed;
	struct hlist_nulls_head	dying;
	struct ip_conntrack_stat *stat;
	int			sysctl_events;
	unsigned int		sysctl_events_retry_timeout;
	int			sysctl_acct;
	int			sysctl_checksum;
	unsigned int		sysctl_log_invalid; /* Log invalid packets */
#ifdef CONFIG_SYSCTL
	struct ctl_table_header	*sysctl_header;
	struct ctl_table_header	*acct_sysctl_header;
	struct ctl_table_header	*event_sysctl_header;
#endif
	int			hash_vmalloc;
	int			expect_vmalloc;
	char			*slabname;
};
#endif
