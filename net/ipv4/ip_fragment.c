/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP fragmentation functionality.
 *
 * Authors:	Fred N. van Kempen <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox <alan@lxorguk.ukuu.org.uk>
 *
 * Fixes:
 *		Alan Cox	:	Split from ip.c , see ip_input.c for history.
 *		David S. Miller :	Begin massive cleanup...
 *		Andi Kleen	:	Add sysctls.
 *		xxxx		:	Overlapfrag bug.
 *		Ultima          :       ip_expire() kernel panic.
 *		Bill Hawes	:	Frag accounting and evictor fixes.
 *		John McDonald	:	0 length frag bug.
 *		Alexey Kuznetsov:	SMP races, threading, cleanup.
 *		Patrick McHardy :	LRU queue of frag heads for evictor.
 */

#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/jiffies.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <net/inet_frag.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/netfilter_ipv4.h>

/* NOTE. Logic of IP defragmentation is parallel to corresponding IPv6
 * code now. If you change something here, _PLEASE_ update ipv6/reassembly.c
 * as well. Or notify me, at least. --ANK
 */

static int sysctl_ipfrag_max_dist __read_mostly = 64;

struct ipfrag_skb_cb
{
	struct inet_skb_parm	h;
	int			offset;
};

#define FRAG_CB(skb)	((struct ipfrag_skb_cb *)((skb)->cb))

/* Describe an entry in the "incomplete datagrams" queue. */
struct ipq {
	struct inet_frag_queue q;

	u32		user;
	__be32		saddr;
	__be32		daddr;
	__be16		id;
	u8		protocol;
	int             iif;
	unsigned int    rid;
	struct inet_peer *peer;
};

static struct inet_frags ip4_frags;

int ip_frag_nqueues(struct net *net)
{
	return net->ipv4.frags.nqueues;
}

int ip_frag_mem(struct net *net)
{
	return atomic_read(&net->ipv4.frags.mem);
}

static int ip_frag_reasm(struct ipq *qp, struct sk_buff *prev,
			 struct net_device *dev);

struct ip4_create_arg {
	struct iphdr *iph;
	u32 user;
};

static unsigned int ipqhashfn(__be16 id, __be32 saddr, __be32 daddr, u8 prot)
{
	return jhash_3words((__force u32)id << 16 | prot,
			    (__force u32)saddr, (__force u32)daddr,
			    ip4_frags.rnd) & (INETFRAGS_HASHSZ - 1);
}

static unsigned int ip4_hashfn(struct inet_frag_queue *q)
{
	struct ipq *ipq;

	ipq = container_of(q, struct ipq, q);
	return ipqhashfn(ipq->id, ipq->saddr, ipq->daddr, ipq->protocol);
}

static int ip4_frag_match(struct inet_frag_queue *q, void *a)
{
	struct ipq *qp;
	struct ip4_create_arg *arg = a;

	qp = container_of(q, struct ipq, q);
	/* 
	    比较indentifier，源地址，目的地址，协议，以及分片队列的所有者。
	    这说明不同所有者，维护了不同的分片队列，它们之间互不影响。
	*/
	return (qp->id == arg->iph->id &&
			qp->saddr == arg->iph->saddr &&
			qp->daddr == arg->iph->daddr &&
			qp->protocol == arg->iph->protocol &&
			qp->user == arg->user);
}

/* Memory Tracking Functions. */
static __inline__ void frag_kfree_skb(struct netns_frags *nf,
		struct sk_buff *skb, int *work)
{
	if (work)
		*work -= skb->truesize;
	atomic_sub(skb->truesize, &nf->mem);
	kfree_skb(skb);
}

static void ip4_frag_init(struct inet_frag_queue *q, void *a)
{
	struct ipq *qp = container_of(q, struct ipq, q);
	struct ip4_create_arg *arg = a;

	qp->protocol = arg->iph->protocol;
	qp->id = arg->iph->id;
	qp->saddr = arg->iph->saddr;
	qp->daddr = arg->iph->daddr;
	qp->user = arg->user;
	qp->peer = sysctl_ipfrag_max_dist ?
		inet_getpeer(arg->iph->saddr, 1) : NULL;
}

static __inline__ void ip4_frag_free(struct inet_frag_queue *q)
{
	struct ipq *qp;

	qp = container_of(q, struct ipq, q);
	if (qp->peer)
		inet_putpeer(qp->peer);
}


/* Destruction primitives. */

static __inline__ void ipq_put(struct ipq *ipq)
{
	inet_frag_put(&ipq->q, &ip4_frags);
}

/* Kill ipq entry. It is not destroyed immediately,
 * because caller (and someone more) holds reference count.
 */
static void ipq_kill(struct ipq *ipq)
{
	inet_frag_kill(&ipq->q, &ip4_frags);
}

/* Memory limiting on fragments.  Evictor trashes the oldest
 * fragment queue until we are back under the threshold.
 */
static void ip_evictor(struct net *net)
{
	int evicted;

	evicted = inet_frag_evictor(&net->ipv4.frags, &ip4_frags);
	if (evicted)
		IP_ADD_STATS_BH(net, IPSTATS_MIB_REASMFAILS, evicted);
}

/*
 * Oops, a fragment queue timed out.  Kill it and send an ICMP reply.
 */
static void ip_expire(unsigned long arg)
{
	struct ipq *qp;
	struct net *net;

	qp = container_of((struct inet_frag_queue *) arg, struct ipq, q);
	net = container_of(qp->q.net, struct net, ipv4.frags);

	spin_lock(&qp->q.lock);

	if (qp->q.last_in & INET_FRAG_COMPLETE)
		goto out;

	ipq_kill(qp);

	IP_INC_STATS_BH(net, IPSTATS_MIB_REASMTIMEOUT);
	IP_INC_STATS_BH(net, IPSTATS_MIB_REASMFAILS);

	if ((qp->q.last_in & INET_FRAG_FIRST_IN) && qp->q.fragments != NULL) {
		struct sk_buff *head = qp->q.fragments;

		/* Send an ICMP "Fragment Reassembly Timeout" message. */
		if ((head->dev = dev_get_by_index(net, qp->iif)) != NULL) {
			icmp_send(head, ICMP_TIME_EXCEEDED, ICMP_EXC_FRAGTIME, 0);
			dev_put(head->dev);
		}
	}
out:
	spin_unlock(&qp->q.lock);
	ipq_put(qp);
}

/* Find the correct entry in the "incomplete datagrams" queue for
 * this IP datagram, and create new one, if nothing is found.
 */
static inline struct ipq *ip_find(struct net *net, struct iphdr *iph, u32 user)
{
	struct inet_frag_queue *q;
	struct ip4_create_arg arg;
	unsigned int hash;

	arg.iph = iph;
	arg.user = user;
	
	/* 
		 这里对获得了ip4_frags.lock的读锁，何时释放的呢？
		 答案是在inet_frag_find这个函数中。
		 这种锁的使用风格很可怕
	 */
	read_lock(&ip4_frags.lock);
	/* 
              对于IP分片来说，使用IP头部信息中的identifier，源地址，目的地址，以及协议来计算hash值。
              一般来说，这     四个值基本上可以保证了IP分片的队列信息的唯一性。不过由于NAT设备的
              使用，就有可能将不同的分片队列混在一起。在计算hash值上，还使用ip4_frags.rnd这一随机值。
       */
	hash = ipqhashfn(iph->id, iph->saddr, iph->daddr, iph->protocol);

	q = inet_frag_find(&net->ipv4.frags, &ip4_frags, &arg, hash);
	if (q == NULL)
		goto out_nomem;
	/* 内核中实际上维护的变量类型为struct ipq，需要从其成员变量q，获得原来的struct ipq类型的地址 */
	return container_of(q, struct ipq, q);

out_nomem:
	LIMIT_NETDEBUG(KERN_ERR "ip_frag_create: no memory left !\n");
	return NULL;
}

/* Is the fragment too far ahead to be part of ipq? */
static inline int ip_frag_too_far(struct ipq *qp)
{
	/* 这个peer端没有弄明白，到底是个什么概念 */
	struct inet_peer *peer = qp->peer;		
	/* 系统默认sysctl_ipfrag_max_dist = 64 ，当然可以修改 */
	unsigned int max = sysctl_ipfrag_max_dist;			
	unsigned int start, end;

	int rc;

	if (!peer || !max)
		return 0;

	start = qp->rid;
	end = atomic_inc_return(&peer->rid);
	/* 如果只是判断end-start的话，为什么这里还要对rid赋值为end，end还是peer->rid +1 */
	qp->rid = end;

	rc = qp->q.fragments && (end - start) > max;

	if (rc) {
		struct net *net;

		net = container_of(qp->q.net, struct net, ipv4.frags);
		IP_INC_STATS_BH(net, IPSTATS_MIB_REASMFAILS);
	}

	return rc;
}

static int ip_frag_reinit(struct ipq *qp)
{
	struct sk_buff *fp;

	if (!mod_timer(&qp->q.timer, jiffies + qp->q.net->timeout)) {
		atomic_inc(&qp->q.refcnt);
		return -ETIMEDOUT;
	}

	fp = qp->q.fragments;
	do {
		struct sk_buff *xp = fp->next;
		frag_kfree_skb(qp->q.net, fp, NULL);
		fp = xp;
	} while (fp);

	qp->q.last_in = 0;
	qp->q.len = 0;
	qp->q.meat = 0;
	qp->q.fragments = NULL;
	qp->iif = 0;

	return 0;
}

/* Add new segment to existing queue. */
static int ip_frag_queue(struct ipq *qp, struct sk_buff *skb)
{
	struct sk_buff *prev, *next;
	struct net_device *dev;
	int flags, offset;
	int ihl, end;
	int err = -ENOENT;

	/* 分片队列已经完成或者即将被清除，都会置上INET_FRAG_COMPLETE */
	if (qp->q.last_in & INET_FRAG_COMPLETE)
		goto err;

	/*
	     1. IPCB(skb)->flags只有在本机发送IPv4分片时 (ip_output.c   ip_fragment函数中)被置位，那么这里的检查应该是
	     预防收到本机自己发出的IP分片。
	     2. 关于ip_frag_too_far：检查碎片是否间隔过远???，如果中间间隔超过64个报文无法完成重组，协议栈就不再支持
	     3. 前面两个条件为真时，调用ip_frag_reinit，重新初始化该队列。出错，那么只好kill掉这个队列了。
       */
	if (!(IPCB(skb)->flags & IPSKB_FRAG_COMPLETE) &&
	    unlikely(ip_frag_too_far(qp)) &&
	    unlikely(err = ip_frag_reinit(qp))) {
		ipq_kill(qp);
		goto err;
	}

	/* 得到分片的数据偏移量及分片标志 */
	offset = ntohs(ip_hdr(skb)->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;		/* offset is in 8-byte chunks */
	ihl = ip_hdrlen(skb);

	/* Determine the position of this fragment. */
	end = offset + skb->len - ihl;
	err = -EINVAL;

	/* Is this the final fragment? */
	if ((flags & IP_MF) == 0) {
		/* If we already have some bits beyond end
		 * or have different end, the segment is corrrupted.
		 */
		/* 这是最后一个分片 */
		/*
	        1. 末尾端要小于之前得到的总的长度，那么肯定出错了；
	        2. 之前已经收到了一个最后分片，且这次判断的末端不等于之前获得的值，那么肯定出错了。
	       */
		if (end < qp->q.len ||
		    ((qp->q.last_in & INET_FRAG_LAST_IN) && end != qp->q.len))
			goto err;
		 /* 置INET_FRAG_LAST_IN标志，表示收到了最后一个分片 */
		qp->q.last_in |= INET_FRAG_LAST_IN;
		 /* IP包总长度就等于end */
		qp->q.len = end;
	} else {
		if (end&7) {
			/* 说明数据长度不是8的倍数。按照协议规定，除最后一个分片外，其余的IP分片的长度必须为8 的倍数*/
            /* 将数据长度缩短为8的倍数的长度 */
			end &= ~7;
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)
				skb->ip_summed = CHECKSUM_NONE;
		}
		if (end > qp->q.len) {
			/* 这次更新的末尾超过了之前的获得长度，进行异常判断，若正常，则更新队列缓存的ip总长度 */
			/* Some bits beyond end -> corruption. */
			/* 
		            如果之前已经获得了最后一个分片，那么总的IP长度一定为正确的值。
		            结果与这次的判断不符，那么一定出错了。
		       */
			if (qp->q.last_in & INET_FRAG_LAST_IN)
				goto err;
			/* 更新IP总长度 */
			qp->q.len = end;
		}
	}
	/* 显然，end应当大于offset 否则ip数据为空, 这里end 肯定不会小于offset，因为协议栈前面ip_rcv()已经进行了ip合法性检查 */
	if (end == offset)
		goto err;

	err = -ENOMEM;
	/* 偏移ip头长度 */
	if (pskb_pull(skb, ihl) == NULL)
		goto err;
	/* 实际调研___pskb_trim()  ___pskb_trim函数针对skb中存在非线性数据的情形，将skb的数据长度裁减到len长度，最终skb->len = len
 * 多余的数据会被clean掉。 */
	err = pskb_trim_rcsum(skb, end - offset);
	if (err)
		goto err;

	/* Find out which fragments are in front and at the back of us
	 * in the chain of fragments so far.  We must know where to put
	 * this fragment, right?
	 */
	 /* 有序挂链 */
	prev = NULL;
	for (next = qp->q.fragments; next != NULL; next = next->next) {
		if (FRAG_CB(next)->offset >= offset)
			break;	/* bingo! */
		prev = next;
	}

	/* We found where to put this one.  Check for overlap with
	 * preceding fragment, and, if needed, align things so that
	 * any overlaps are eliminated.
	 */
	 /* 现在已经找到了正确的插入位置，但是可能与已有的IP分片重叠，下面需要处理overlap 重叠问题 */ 
	if (prev) {
		int i = (FRAG_CB(prev)->offset + prev->len) - offset;

		if (i > 0) {
			 /* 与前一个分片有重叠，那么新的偏移量为上一个分片的末尾 */
			offset += i;
			err = -EINVAL;
			 /* end如果小于了新的偏移，出错了，drop掉这个分片 */
			if (end <= offset)
				goto err;
			err = -ENOMEM;
			if (!pskb_pull(skb, i))
				goto err;
			/* 使checksum无效 */
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)
				skb->ip_summed = CHECKSUM_NONE;
		}
	}

	err = -ENOMEM;

	while (next && FRAG_CB(next)->offset < end) {
		/* 与已有的后面的IP分片重叠，这里使用while循环，是因为可能与多个重叠
		这里的初始next是挂链节点的后一个节点*/
		int i = end - FRAG_CB(next)->offset; /* overlap is 'i' bytes */

		if (i < next->len) {
			/* 与后面的IP分片头部重叠。那么就更新后面的IP分片的偏移即可。这时无需继续测试，可以跳出循 环 */ 
			/* Eat head of the next overlapped fragment
			 * and leave the loop. The next ones cannot overlap.
			 */
			if (!pskb_pull(next, i))
				goto err;
			FRAG_CB(next)->offset += i;
			qp->q.meat -= i;
			if (next->ip_summed != CHECKSUM_UNNECESSARY)
				next->ip_summed = CHECKSUM_NONE;
			break;
		} else {
		/* 重叠部分覆盖已有的IP分片，那么可以将已有的IP分片释放， 然后继续测试下一个分片 */
			struct sk_buff *free_it = next;

			/* Old fragment is completely overridden with
			 * new one drop it.
			 */
			next = next->next;

			if (prev)
				prev->next = next;
			else
				qp->q.fragments = next;

			qp->q.meat -= free_it->len;
			frag_kfree_skb(qp->q.net, free_it, NULL);
		}
	}
	/* 已经处理完了重叠问题，offset为新的偏移量 */
	FRAG_CB(skb)->offset = offset;

	/* Insert this fragment in the chain of fragments. */
	skb->next = next;
	if (prev)
		prev->next = skb;
	else
		qp->q.fragments = skb;

	dev = skb->dev;
	if (dev) {
		qp->iif = dev->ifindex;
		skb->dev = NULL;
	}
	qp->q.stamp = skb->tstamp;
	qp->q.meat += skb->len;
	atomic_add(skb->truesize, &qp->q.net->mem);
	/* 偏移为0，说明是第一个分片 */
	if (offset == 0)
		qp->q.last_in |= INET_FRAG_FIRST_IN;
	/* 
		如果已经收到了第一个分片和最后一个分片，且收到的IP分片的长度也等于了原始的IP长度。
		那么说明一切就绪，可以重组IP分片了。
	*/
	if (qp->q.last_in == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
	    qp->q.meat == qp->q.len)
		return ip_frag_reasm(qp, prev, dev);
	/* IP分片还未全部收齐 */
	write_lock(&ip4_frags.lock);
	list_move_tail(&qp->q.lru_list, &qp->q.net->lru_list);
	write_unlock(&ip4_frags.lock);
	return -EINPROGRESS;

err:
	kfree_skb(skb);
	return err;
}


/* Build a new IP datagram from all its fragments. */
/*  分片重组具体函数  */
static int ip_frag_reasm(struct ipq *qp, struct sk_buff *prev,
			 struct net_device *dev)
{
	struct net *net = container_of(qp->q.net, struct net, ipv4.frags);
	struct iphdr *iph;
	struct sk_buff *fp, *head = qp->q.fragments;
	int len;
	int ihlen;
	int err;
	/* kill掉该IP队列 */
	ipq_kill(qp);

	/* Make the one we just received the head. */
	/* 当prev不为null时，head=prev->next，即当前收到的这个分片，也就是把刚收到的这个分片当作head。
	当prev为null时，qp->q.fragments就是刚收到的分片 */
	if (prev) {
		 /* 
	        如果最后插入的分片不是第一个分片，前面还有分片，
	        将最后插入的分片作为整个分片队列的第一个分片
	        */
		head = prev->next;
		fp = skb_clone(head, GFP_ATOMIC);
		if (!fp)
			goto out_nomem;

		fp->next = head->next;
		prev->next = fp;
		/*
		由于已经用fp代替了head，将head变异为队列中第一个数据分组，
		即清空其原来内容，只保留一个sk_buff框架，然后复制第一个数据分片内容
		*/	
		skb_morph(head, qp->q.fragments);
		head->next = qp->q.fragments->next;
		/* 
		释放原来的第一个数据分片结构
		*/
		kfree_skb(qp->q.fragments);	
		qp->q.fragments = head;
	}
	/* 
		 ok，现在head肯定为刚刚收到的分片。
		 大胆猜测一下用意，因为刚收到的IP分片里面的IP信息是最新的，
		 所有选择它作为head，用于生成重组后的IP包。
		 比如也许会有一些新的IP option等。
	*/

	WARN_ON(head == NULL);
	WARN_ON(FRAG_CB(head)->offset != 0);

	/* Allocate a new buffer for the datagram. */
	ihlen = ip_hdrlen(head);
	len = ihlen + qp->q.len;

	err = -E2BIG;
	/* 如果主数据块大于65536字节，出错，说明tcp\udp数据报最大长度为64K */
	if (len > 65535)
		goto out_oversize;

	/* Head of list must not be cloned. */
	/*
	验证内存空间确保有必要空间，因为重组分片需要申请新的内存空间；
	第一个数据报分片作为主数据报结构，确保该数据报分片的正确性
	*/
	if (skb_cloned(head) && pskb_expand_head(head, 0, 0, GFP_ATOMIC))
		goto out_nomem;

	/* If the first fragment is fragmented itself, we split
	 * it to two chunks: the first with data and paged part
	 * and the second, holding only fragments. */
	 //如果第一个数据分片中有分片数据，将她的分片转移到ip分片队列中
	if (skb_has_frags(head)) {
		/* 
		这里的分片不同于IP分片。因为skb存储数据的时候有两种方式，
		一个是存储在skb自身的空间，另外一 种是申请一个page，
		数据存储在该page中。当使用后者的方式时，skb_has_frags为true 
		*/
 		struct sk_buff *clone;
		int i, plen = 0;

		if ((clone = alloc_skb(0, GFP_ATOMIC)) == NULL)
			goto out_nomem;
		clone->next = head->next;
		head->next = clone;
		skb_shinfo(clone)->frag_list = skb_shinfo(head)->frag_list;
		skb_frag_list_init(head);
		for (i=0; i<skb_shinfo(head)->nr_frags; i++)
			plen += skb_shinfo(head)->frags[i].size;
		clone->len = clone->data_len = head->data_len - plen;
		head->data_len -= clone->len;
		head->len -= clone->len;
		clone->csum = 0;
		clone->ip_summed = head->ip_summed;
		atomic_add(clone->truesize, &qp->q.net->mem);
	}
	/* 
     将后面的分片赋给head->frag_list。
     这里所做的IP分片重组，并不是真的生成一个完整的独立的IP分片，而是将后面的分片挂载到head分片的frag_list上。
     */
     // 实际上是skb_shinfo(head)->frag_list = qp->q.fragments->next;
	skb_shinfo(head)->frag_list = head->next;
	//调整第一个分片的数据分片起始位置，使其包含ip头部
	skb_push(head, head->data - skb_network_header(head));
	atomic_sub(head->truesize, &qp->q.net->mem);

	for (fp=head->next; fp; fp = fp->next) {
		/* 形成整体数据报的结构，存于head中，分片从下一个开始 */

		//累加每一个数据分片长度
		head->data_len += fp->len;
		head->len += fp->len;
		if (head->ip_summed != fp->ip_summed)
			head->ip_summed = CHECKSUM_NONE;
		else if (head->ip_summed == CHECKSUM_COMPLETE)
			head->csum = csum_add(head->csum, fp->csum);
		//主数据分片的实际长度[大于len，实际分配的内存]累加每一个分片的实际长度
		head->truesize += fp->truesize;
		atomic_sub(fp->truesize, &qp->q.net->mem);
	}
	//断开与分片队列的关系
	head->next = NULL;
	head->dev = dev;
	//记录时间戳
	head->tstamp = qp->q.stamp;
	/*
	修复主数据报的IP头部结构,可见对一个分组后的每个ip分片而言，
	其各自的ip头部中tot_len为该分片中的数据长度+ip头部长度，显然小于1500MTU值，
	而整合分片时，所有分片组合后的最终总和由前面代码看出必须小于65536，
	所以当从传输层传下来数据时，大小必须小于65530，
	即udp和tcp中每次传输文件的大小小于65536。
	*/
	//取得主数据包的IP头部结构，刚才sk_buff->data前移包含了ip头部
	iph = ip_hdr(head);
	iph->frag_off = 0;
	// len=ihlen + qp->q.len,此时tot_len字段为整个数据报的长度[含ip头部]
	iph->tot_len = htons(len);
	IP_INC_STATS_BH(net, IPSTATS_MIB_REASMOKS);
	qp->q.fragments = NULL;
	return 0;

out_nomem:
	LIMIT_NETDEBUG(KERN_ERR "IP: queue_glue: no memory for gluing "
			      "queue %p\n", qp);
	err = -ENOMEM;
	goto out_fail;
out_oversize:
	if (net_ratelimit())
		printk(KERN_INFO "Oversized IP packet from %pI4.\n",
			&qp->saddr);
out_fail:
	IP_INC_STATS_BH(net, IPSTATS_MIB_REASMFAILS);
	return err;
}

/* Process an incoming IP datagram fragment. */
int ip_defrag(struct sk_buff *skb, u32 user)
{
	struct ipq *qp;
	struct net *net;

	/* 获取net命名空间，估计是内核新增加的功能 */
	net = skb->dev ? dev_net(skb->dev) : dev_net(skb_dst(skb)->dev);
	IP_INC_STATS_BH(net, IPSTATS_MIB_REASMREQDS);

	/* Start by cleaning up the memory. */
	/* 
       IP分片占用的内存已经超过了设定的最高阀值，需要回收内存。
       这个是必不可少的。因为所以的未重组的IP分片都保存在内存中。
      */ 
	if (atomic_read(&net->ipv4.frags.mem) > net->ipv4.frags.high_thresh)
		ip_evictor(net);

	/* Lookup (or create) queue header */
	/* 查找对应的IP分片队列 */
	if ((qp = ip_find(net, ip_hdr(skb), user)) != NULL) {
		int ret;

		spin_lock(&qp->q.lock);
		/* 将skb分片报文挂链到查找到的qp上 */
		ret = ip_frag_queue(qp, skb);

		spin_unlock(&qp->q.lock);
		ipq_put(qp);
		return ret;
	}

	/* 无法创建新的IP分片队列，说明内存不足 */
	IP_INC_STATS_BH(net, IPSTATS_MIB_REASMFAILS);
	kfree_skb(skb);
	return -ENOMEM;
}

#ifdef CONFIG_SYSCTL
static int zero;

static struct ctl_table ip4_frags_ns_ctl_table[] = {
	{
		.ctl_name	= NET_IPV4_IPFRAG_HIGH_THRESH,
		.procname	= "ipfrag_high_thresh",
		.data		= &init_net.ipv4.frags.high_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.ctl_name	= NET_IPV4_IPFRAG_LOW_THRESH,
		.procname	= "ipfrag_low_thresh",
		.data		= &init_net.ipv4.frags.low_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.ctl_name	= NET_IPV4_IPFRAG_TIME,
		.procname	= "ipfrag_time",
		.data		= &init_net.ipv4.frags.timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
		.strategy	= sysctl_jiffies
	},
	{ }
};

static struct ctl_table ip4_frags_ctl_table[] = {
	{
		.ctl_name	= NET_IPV4_IPFRAG_SECRET_INTERVAL,
		.procname	= "ipfrag_secret_interval",
		.data		= &ip4_frags.secret_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
		.strategy	= sysctl_jiffies
	},
	{
		.procname	= "ipfrag_max_dist",
		.data		= &sysctl_ipfrag_max_dist,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero
	},
	{ }
};

static int ip4_frags_ns_ctl_register(struct net *net)
{
	struct ctl_table *table;
	struct ctl_table_header *hdr;

	table = ip4_frags_ns_ctl_table;
	if (net != &init_net) {
		table = kmemdup(table, sizeof(ip4_frags_ns_ctl_table), GFP_KERNEL);
		if (table == NULL)
			goto err_alloc;

		table[0].data = &net->ipv4.frags.high_thresh;
		table[1].data = &net->ipv4.frags.low_thresh;
		table[2].data = &net->ipv4.frags.timeout;
	}

	hdr = register_net_sysctl_table(net, net_ipv4_ctl_path, table);
	if (hdr == NULL)
		goto err_reg;

	net->ipv4.frags_hdr = hdr;
	return 0;

err_reg:
	if (net != &init_net)
		kfree(table);
err_alloc:
	return -ENOMEM;
}

static void ip4_frags_ns_ctl_unregister(struct net *net)
{
	struct ctl_table *table;

	table = net->ipv4.frags_hdr->ctl_table_arg;
	unregister_net_sysctl_table(net->ipv4.frags_hdr);
	kfree(table);
}

static void ip4_frags_ctl_register(void)
{
	register_net_sysctl_rotable(net_ipv4_ctl_path, ip4_frags_ctl_table);
}
#else
static inline int ip4_frags_ns_ctl_register(struct net *net)
{
	return 0;
}

static inline void ip4_frags_ns_ctl_unregister(struct net *net)
{
}

static inline void ip4_frags_ctl_register(void)
{
}
#endif

static int ipv4_frags_init_net(struct net *net)
{
	/*
	 * Fragment cache limits. We will commit 256K at one time. Should we
	 * cross that limit we will prune down to 192K. This should cope with
	 * even the most extreme cases without allowing an attacker to
	 * measurably harm machine performance.
	 */
	net->ipv4.frags.high_thresh = 256 * 1024;
	net->ipv4.frags.low_thresh = 192 * 1024;
	/*
	 * Important NOTE! Fragment queue must be destroyed before MSL expires.
	 * RFC791 is wrong proposing to prolongate timer each fragment arrival
	 * by TTL.
	 */
	net->ipv4.frags.timeout = IP_FRAG_TIME;

	inet_frags_init_net(&net->ipv4.frags);

	return ip4_frags_ns_ctl_register(net);
}

static void ipv4_frags_exit_net(struct net *net)
{
	ip4_frags_ns_ctl_unregister(net);
	inet_frags_exit_net(&net->ipv4.frags, &ip4_frags);
}

static struct pernet_operations ip4_frags_ops = {
	.init = ipv4_frags_init_net,
	.exit = ipv4_frags_exit_net,
};

void __init ipfrag_init(void)
{
	ip4_frags_ctl_register();
	register_pernet_subsys(&ip4_frags_ops);
	ip4_frags.hashfn = ip4_hashfn;
	ip4_frags.constructor = ip4_frag_init;
	ip4_frags.destructor = ip4_frag_free;
	ip4_frags.skb_free = NULL;
	ip4_frags.qsize = sizeof(struct ipq);
	ip4_frags.match = ip4_frag_match;
	ip4_frags.frag_expire = ip_expire;
	ip4_frags.secret_interval = 10 * 60 * HZ;
	inet_frags_init(&ip4_frags);
}

EXPORT_SYMBOL(ip_defrag);
