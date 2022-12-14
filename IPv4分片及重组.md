# IPv4分片及重组详解

[toc]
## 1.IPv4分片
### 1.1 IPv4分片情况分类
分段是网络层的一个重要任务，网络层需要对两方面的IP数据包进行分段：

**（1）本地产生的数据包**：对于本机发送的数据包，TCP在组织skb数据时，本身就会考虑MTU的限制，它会尽可能的保证每个skb携带的数据不会超过MTU，就是为了避免网络层再进行分段，因为分段对TCP性能的影响较大。因为TCP就帮忙做了很多事情，所以对于TCP发送场景，应该是很少有机会执行分片的。考虑UDP，它并不会向TCP一样保证skb长度，但是由于UDP往往是调用ip_append_data()组织skb数据的，该函数在组织skb过程中，会将属于同一个IP报文的所有分片都组织成skb列表（非第一个分片都放在第一个分片skb的frag_list中），这样网络层在执行分片时将会节省很多工作量。

**（2）转发的数据包**：对于转发的数据包，则无法向本地发送一样，提前做很多的工作，网络层必须依靠自己来兼容所有可能的情况。同样的，对于一些特殊的异常场景，本机发送的数据包也有可能并没有按照预期情况组织，这时网络层也要能够兼容处理。

综上，网络层在实现分段时，设计了**快速路径和慢速路径**两个流程来分别对应上面的两种情况。

### 1.2 IP分片 ip_fragment()
```c
static int ip_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
		       unsigned int mtu,
		       int (*output)(struct net *, struct sock *, struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);

	if ((iph->frag_off & htons(IP_DF)) == 0)
		return ip_do_fragment(net, sk, skb, output);
	// 一旦进入该函数，说明skb过大，需要进行IP分片，但是又设置了DF标记或者本身是抑制分片的，
	// 那么发送失败，向源端发送ICMP报文，这里主要是为forward数据所判断。
	if (unlikely(!skb->ignore_df ||
		     (IPCB(skb)->frag_max_size &&
		      IPCB(skb)->frag_max_size > mtu))) {
		IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(mtu));
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	return ip_do_fragment(net, sk, skb, output);
}


int ip_do_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
		   int (*output)(struct net *, struct sock *, struct sk_buff *))
{
	struct iphdr *iph;
	int ptr;
	struct sk_buff *skb2;
	unsigned int mtu, hlen, left, len, ll_rs;
	int offset;
	__be16 not_last_frag;
	struct rtable *rt = skb_rtable(skb);
	int err = 0;

	/* for offloaded checksums cleanup checksum before fragmentation */
	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    (err = skb_checksum_help(skb)))
		goto fail;

	iph = ip_hdr(skb);

	mtu = ip_skb_dst_mtu(sk, skb);
	if (IPCB(skb)->frag_max_size && IPCB(skb)->frag_max_size < mtu)
		mtu = IPCB(skb)->frag_max_size;
	hlen = iph->ihl * 4;
	// 这里 mtu代表每个IP片段能够容纳的L4载荷，所以需要在MTU基础上去掉IP首部的开销
	mtu = mtu - hlen;	/* Size of data space */
	IPCB(skb)->flags |= IPSKB_FRAG_COMPLETE;
	ll_rs = LL_RESERVED_SPACE(rt->dst.dev);
	 
	/*
	 * 如果4层将数据包分片了，那么就会把这些数据包放到skb的frag_list链表中，
	 * 因此这里首先先判断frag_list链表是否为空，为空的话将会进行slow 分片
	 */
	if (skb_has_frag_list(skb)) {
		struct sk_buff *frag, *frag2;
		
		/*
		 * 取得第一个数据报的len.当sk_write_queue队列被flush后，
		 * 除了第一个切好包的另外的包都会加入到frag_list中(接口ip_push_pending_frames)，
		 * 而这里需要得到的第一个包(也就是本身这个sk_buff）的长度。
		 * first_len是第一个skb中所有数据的总长度，包括线性缓冲区和frags[]数组
		 */

		unsigned int first_len = skb_pagelen(skb);

		/*
		 * 接下来的判断都是为了确定能进行fast分片。分片不能被共享，
		 * 这是因为在fast path 中，需要加给每个分片不同的ip头(而并
		 * 不会复制每个分片)。因此在fast path中是不可接受的。而在
		 * slow path中，就算有共享也无所谓，因为他会复制每一个分片，
		 * 使用一个新的buff。   
		 */
		
  		/*
		 * 判断第一个包长度是否符合一些限制(包括mtu，mf位等一些限制).
		 * 如果第一个数据报的len没有包含mtu的大小这里之所以要把第一个
		 * 切好片的数据包单独拿出来检测，是因为一些域是第一个包所独有
		 * 的(比如IP_MF要为1）。这里由于这个mtu是不包括hlen的mtu，因此
		 * 需要减去一个hlen。  
  		 */
 
		/*
		 * 1. 条件1说明高层协议切割的skb的长度还是太长了；
		 * 2. 第一个片段长度必须是8字节对齐的（IP片段偏移量是8字节对齐决定的）；
		 * 3. 偏移量在下面的分段过程中才会进行设置，这里不应该有值；
		 * 4. skb不能是被共享的，因为快速路径上不会进行skb拷贝，而是直接修改skb；
		 * 上述4个条件有任何一个不满足，那么就用慢速路径完成分片
		 */
		if (first_len - hlen > mtu ||
		    ((first_len - hlen) & 7) ||
		    ip_is_fragment(iph) ||
		    skb_cloned(skb) ||
		    skb_headroom(skb) < ll_rs)
			goto slow_path;
			
		// 遍历frag_list列表，检查是否所有的分片是否符合快速分片处理
		skb_walk_frags(skb, frag) {
			/* Correct geometry. */
			if (frag->len > mtu ||
			    ((frag->len & 7) && frag->next) ||
			    skb_headroom(frag) < hlen + ll_rs)
				goto slow_path_clean;

			/* Partially cloned skb? */
			if (skb_shared(frag))
				goto slow_path_clean;

			BUG_ON(frag->sk);
			if (skb->sk) {
				frag->sk = skb->sk;
				frag->destructor = sock_wfree;
			}
			skb->truesize -= frag->truesize;
		}

		// 对第一个分片的特殊处理
		err = 0;
		offset = 0;
		frag = skb_shinfo(skb)->frag_list;
		skb_frag_list_init(skb);
		skb->data_len = first_len - skb_headlen(skb);
		skb->len = first_len;
		iph->tot_len = htons(first_len);
		iph->frag_off = htons(IP_MF);
		ip_send_check(iph);
		// 循环处理后面所有的分片
		for (;;) {
			/* Prepare header of the next frame,
			 * before previous one went down. */
			if (frag) {
				frag->ip_summed = CHECKSUM_NONE;
				skb_reset_transport_header(frag);
				__skb_push(frag, hlen);
				skb_reset_network_header(frag);
				memcpy(skb_network_header(frag), iph, hlen);
				iph = ip_hdr(frag);
				iph->tot_len = htons(frag->len);
				ip_copy_metadata(frag, skb);
				if (offset == 0)
					ip_options_fragment(frag);
				offset += skb->len - hlen;
				iph->frag_off = htons(offset>>3);
				if (frag->next)
					iph->frag_off |= htons(IP_MF);
				/* Ready, complete checksum */
				ip_send_check(iph);
			}
			// 继续发送过程,先发送首片ip的skb自己，后面继续发送frag
			err = output(net, sk, skb);

			if (!err)
				IP_INC_STATS(net, IPSTATS_MIB_FRAGCREATES);
			if (err || !frag)
				break;

			skb = frag;
			frag = skb->next;
			skb->next = NULL;
		}
		// 一切正常，分片过程从这里返回	
		if (err == 0) {
			IP_INC_STATS(net, IPSTATS_MIB_FRAGOKS);
			return 0;
		}
		// 分片或者发送过程失败了，释放所有的skb分片
		while (frag) {
			skb = frag->next;
			kfree_skb(frag);
			frag = skb;
		}
		IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
		return err;

slow_path_clean:
		skb_walk_frags(skb, frag2) {
			if (frag2 == frag)
				break;
			frag2->sk = NULL;
			frag2->destructor = NULL;
			skb->truesize += frag2->truesize;
		}
	}

slow_path:
	iph = ip_hdr(skb);
	// left保存整个IP报文中剩余需要分段的报文长度，在下面分段过程中会逐渐减小，
	// 直到为0说明分段过程结束
	left = skb->len - hlen;	
	// ptr指向L4载荷的偏移，初始值指向L4报文的开头
	ptr = raw + hlen;
	// offset为偏移量，不包括DF、MF标记
	offset = (ntohs(iph->frag_off) & IP_OFFSET) << 3;
	// 标识是否是IP报文的最后一个片段，因为最后一个片段的MF标记是0
	not_last_frag = iph->frag_off & htons(IP_MF);
	// 循环创建新的skb2，然后拷贝数据，完成分段（left==0）
	while (left > 0) {
		// 调整len为本轮循环分片中能够容纳的L4报文载荷长度
		len = left;
		/* IF: it doesn't fit, use 'mtu' - the data space left */
		if (len > mtu)
			len = mtu;
		// IP报文首部的片偏移字段格式决定了非最后一个IP片段的偏移量必须是8字节对齐的
		if (len < left)	{
			len &= ~7;
		}
 
		// 分配skb2，长度包括三部分:len代表的L4报文部分；hlen代表的IP报文首部；ll_rs代表的L2报文首部
		if ((skb2 = alloc_skb(len+hlen+ll_rs, GFP_ATOMIC)) == NULL) {
			NETDEBUG(KERN_INFO "IP: frag: no memory for new fragment!\n");
			err = -ENOMEM;
			goto fail;

		// 首先设置skb2中的各个字段
		ip_copy_metadata(skb2, skb);
		skb_reserve(skb2, ll_rs);
		skb_put(skb2, len + hlen);
		skb_reset_network_header(skb2);
		skb2->transport_header = skb2->network_header + hlen;
		// 设置owner，内存的消耗将会记录到owner的账上
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
 
		// 先从源skb的线性缓冲区将IP报文首部拷贝到skb2的线性缓冲区，因为内存上是连续的，
		// 所以直接使用memcpy拷贝即可
		skb_copy_from_linear_data(skb, skb_network_header(skb2), hlen);
 
		// 下面的数据拷贝就复杂了一些，因为慢速路径要能够处理任何可能的skb的数据组织方式。
		// skb_copy_bits()将从skb->data开始偏移的ptr位置开始拷贝数据，共拷贝len字节到
		// skb2传输层开始的位置，注意这里在处理ptr偏移会考虑页缓冲区和frag_list两种情况
		if (skb_copy_bits(skb, ptr, skb_transport_header(skb2), len))
			BUG();
		// 分段完成，left减去1个片段的长度
		left -= len;

		 // 填充IP首部，主要是选项和偏移字段
		iph = ip_hdr(skb2);
		iph->frag_off = htons((offset >> 3));

		if (IPCB(skb)->flags & IPSKB_FRAG_PMTU)
			iph->frag_off |= htons(IP_DF);

		// ip_options_fragment()会在第一个IP片段的基础上将后面片段不需要的IP选项删除，
		// 这样后面的IP片段直接继承即可（前面已经拷贝），无需重新设定选项，所以这里只
		// 在第一个片段分片过程中调用ip_options_fragment()
		if (offset == 0)
			ip_options_fragment(skb);

		// 不是最后一个包，因此设置mf位
		if (left > 0 || not_last_frag)
			iph->frag_off |= htons(IP_MF);
		// 更新ptr和offset，为下一个分片做好准备
		ptr += len;
		offset += len;

		// IP首部的total字段表示的是IP片段的长度
		iph->tot_len = htons(len + hlen);
		// 计算IP首部校验和
		ip_send_check(iph);
		// 调用发送接口继续发送过程
		err = output(net, sk, skb2);
		if (err)
			goto fail;

		IP_INC_STATS(net, IPSTATS_MIB_FRAGCREATES);
	}
	
	// 原有的IP报文都已经被分割成一个个新的skb，所以处理结束后，原来的skb需要释放
	consume_skb(skb);
	IP_INC_STATS(net, IPSTATS_MIB_FRAGOKS);
	return err;

fail:
	kfree_skb(skb);
	IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
	return err;
}
```

## 2.IPv4分片重组
### 2.1 IP分片重组控制信息数据结构
#### 2.1.1 网络命名空间struct netns_ipv4
```c
struct net {
...
    struct netns_ipv4	ipv4;
}
struct netns_ipv4 {
...
    struct netns_frags frags;
}
struct netns_frags {
    // 当前保存的所有待重组分片占用的全部内存，不仅仅是分片本身的大小，还有为了管理而增加的额外开销,
    // 该值不允许超过下面的上限值high_thresh，超过后，后续的IP片段将会由于没有内存而被丢弃
    atomic_t mem;
    // 配置参数/proc/sys/net/ipv4/ipfrag_time，默认30s,分片超时时间
    int	timeout;
    // 配置参数/proc/sys/net/ipv4/ipfrag_high_thresh
    int	high_thresh;
...
};
```
#### 2.1.2 IPV4协议用于分片重组的全局哈希表信息 struct inet_frags
在内核中同时存在很多需要重组的IP数据包，理论上最大值为1024×128。Linux内核根据接收到的分片的IP头相关信息计算得到一个哈希值，将该值转化到0~1023找到IP分片队列链表。遍历链表找到对应的IP分片队列，若不存在则新建一个IP分片队列。
```c
//哈希值范围0~1023
#define INETFRAGS_HASHSZ	1024
//每个哈希值对应一个IP分片队列链表，该链表最大长度为128,该值会被high_thresh参数影响
#define INETFRAGS_MAXDEPTH	128

//指向IP分片队列链表头
struct hlist_head {
    struct hlist_node *first;
};

struct inet_frag_bucket {
    struct hlist_head	chain;
    spinlock_t	 chain_lock;
};

struct inet_frags {
    // 所有待重组的IP分片队列在该哈希表中
    struct inet_frag_bucket	hash[INETFRAGS_HASHSZ];
...
};
```
#### 2.1.3 IP分片队列 struct ipq [struct inet_frag_queue]
```c
//每个ipq结构体表示一个IP分片队列
struct ipq {
    //详细描述IP分片队列中的相关信息
    struct inet_frag_queue q;
...
};

struct hlist_node {
    struct hlist_node *next, **pprev;
};

enum {
    INET_FRAG_FIRST_IN= BIT(0), // 值1，第一个分片
    INET_FRAG_LAST_IN	= BIT(1), // 值2，最后一个分片
    INET_FRAG_COMPLETE= BIT(2), // 值4，全部分片接收完成
};

struct inet_frag_queue {
    struct timer_list	timer;//定时器，超时未重组所有片段会被丢弃
    struct hlist_node	list;// 将IP分片队列接入全局哈希表对应哈希值的IP分片队列链表
    refcount_t		refcnt;//引用计数，每个IP片段都会持有一个该队列的引用计数
    struct sk_buff	*fragments;//始终指向skb队列的队头
    struct sk_buff	*fragments_tail; //目前接收到的最后一个分片，位于skb队列的队尾
    int		len; //当前收到所有IP分片中的最大偏移量
    int		meat;//当前已经收到的IP分片的数据量总和
    __u8      flags;  //记录分片重组的状态，理论上共8种状态
    struct netns_frags *net;// 指向网络命名空间中的net->ipv4.frags
...
};
```
#### 2.1.4 上述数据结构之间的关系

![IP分片重组数据结构](https://github.com/zjc0000/story_images/raw/main/小书匠/1663649025103.png)
### 2.2 IP分片重组完整流程
#### 2.2.1 IP片段接收入口ip_local_deliver()
 ```c
 int ip_local_deliver(struct sk_buff *skb)
{	
    struct net *net = dev_net(skb->dev);
    //判断数据包是否为一个分组
    if (ip_is_fragment(ip_hdr(skb))) {
	//进行分片重组，ip_defrag成功返回0，需要将最后一个分片skb处理成重组好的包提交
	if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
		return 0;
	}
    return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN, net, NULL, skb, skb->dev, NULL,ip_local_deliver_finish);
}
#define IP_MF		0x2000
#define IP_OFFSET	0x1FFF
static inline bool ip_is_fragment(const struct iphdr *iph)
{
	//只有当段偏移量为0且MF位为0时说明没有进行分片，此时返回0，否则有分片，此时返回1
	return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}
 ```

#### 2.2.2 IP片段重组 ip_defrag()
 ```c
 int ip_defrag(struct net *net, struct sk_buff *skb, u32 user)
{
    ......
    //查找是否已经在分组队列里存在相应的queue
    //如果没有那么就新建一个queue等待收集之后的报文，如果已经存在那么就返回queue的入口
    qp = ip_find(net, ip_hdr(skb), user, vif);
    if (qp) {
        ......
        // 尝试进行分片重组，如果能够重组出一个完整的IP报文，则返回0，这样数据包就会传递给L4协议
	ret = ip_frag_queue(qp, skb);
        ......
	}
    ......
}
 ```
 
#### 2.2.3 查找IP分片队列 ip_find()
```c
static struct ipq *ip_find(struct net *net, struct iphdr *iph,u32 user, int vif)
{
    ......
	// 根据ipid、源IP、目的IP、L4协议号以及初始化时生成的一个随机数共5个信息计算hash值
	hash = ipqhashfn(iph->id, iph->saddr, iph->daddr, iph->protocol);
	// 查找哈希值对应的IP分片队列链表，检查是否有该片段所属报文对应的IP分片队列，如果没有那么函数会新建并将其链表
	q = inet_frag_find(&net->ipv4.frags, &ip4_frags, &arg, hash);
    ......
}

struct inet_frag_queue *inet_frag_find(struct netns_frags *nf,
	struct inet_frags *f, void *key,unsigned int hash)
{
    ......
    //将计算得到的hash值转化到（0~INETFRAGS_HASHSZ - 1）之间，即可找到该hash值对应的IP分片队列链表
    hash &= (INETFRAGS_HASHSZ - 1);
    hb = &f->hash[hash];
    // 遍历IP分片队列链表，寻找匹配的IP分片队列，如果找到增加引用计数并返回
    hlist_for_each_entry(q, &hb->chain, list) {
	if (q->net == nf && f->match(q, key)) {
            refcount_inc(&q->refcnt);
	    spin_unlock(&hb->chain_lock);
	    return q;
	}
	depth++;
    }
    //找不到则创建，IP分片队列总数不能超过最大深度
    if (depth <= INETFRAGS_MAXDEPTH)
	return inet_frag_create(nf, f, key);
    ......
}

static struct inet_frag_queue *inet_frag_create(struct netns_frags *nf,struct inet_frags *f,void *arg)
{
    struct inet_frag_queue *q;
    // 分配IP分片队列并对其进行初始化
    q = inet_frag_alloc(nf, f, arg);
    if (!q)
        	return NULL;
    // 将新建的IP分片队列放入全局的IP分片重组哈希表中
    return inet_frag_intern(nf, q, f, arg);
}
```
#### 2.2.4 重组IP报文 ip_frag_queue()
```c
static int ip_frag_queue(struct ipq *qp, struct sk_buff *skb)
{
	struct sk_buff *prev, *next;
	struct net_device *dev;
	unsigned int fragsize;
	int flags, offset;
	int ihl, end;
	int err = -ENOENT;
	u8 ecn;

	//如果IP报文已经重组完成但是又收到属于它的片段，那么一定是重复分片，直接丢弃
	if (qp->q.flags & INET_FRAG_COMPLETE)
		goto err;

	if (!(IPCB(skb)->flags & IPSKB_FRAG_COMPLETE) &&
	    unlikely(ip_frag_too_far(qp)) &&
	    unlikely(err = ip_frag_reinit(qp))) {
		ipq_kill(qp);
		goto err;
	}
	ecn = ip4_frag_ecn(ip_hdr(skb)->tos);


	offset = ntohs(ip_hdr(skb)->frag_off);
	//取得IP分片的相关标志位（&0xe000）
	flags = offset & ~IP_OFFSET;
	//取得IP分片负载第一个字节偏移量，以8字节为单位
	offset &= IP_OFFSET;
	offset <<= 3;	

	ihl = ip_hdrlen(skb);

	/*
	 * IP层分片是对IP的负载进行分片，即只有第一个分片包含L4层头
	 * (skb->len - ihl)是当前分片的IP负载长度与当前分片的偏移量相加
	 * skb_network_offset(skb) = 0，之前的内核版本无此部分
	 * end表示当前分片的负载最后一个字节的偏移量
	*/
	end = offset + skb->len - skb_network_offset(skb) - ihl;
	err = -EINVAL;

	if ((flags & IP_MF) == 0) {
		/*
		 * MF标记为0说明为IP报文的最后一个分片
		 * q.len字段记录的是当前收到所有片段中的最大偏移量，片段到来的顺序是随机的
		*/		
		if (end < qp->q.len ||
		    ((qp->q.flags & INET_FRAG_LAST_IN) && end != qp->q.len))
			goto err;
		
		//标记接收到最后一个片段，更新len字段
		qp->q.flags |= INET_FRAG_LAST_IN;
		qp->q.len = end;
	} else {
		//IP分片不是最后一个分片，则end一定是8字节对齐的，end&7的值一定为0
		if (end&7) {
			end &= ~7;//如果不满足字节对齐，end更新为当前最大的字节对齐数，之后的数据会被丢弃
			//CHECKSUM_NONE表示让L4层重新计算校验和
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)
				skb->ip_summed = CHECKSUM_NONE;
		}
		if (end > qp->q.len) {
			//最后一个分片但其MF标志位不为0，出错
			if (qp->q.flags & INET_FRAG_LAST_IN)
				goto err;
			qp->q.len = end;
		}
	}

	//成立则说明（1）本IP分片没有携带数据（2）携带数据0~7字节被舍弃掉相当于没有数据
	if (end == offset)
		goto err;
	err = -ENOMEM;

	// 调整skb的data指针，删除IP首部，只保留数据部分，此时data指针指向IP头之后的第一个字节，之后所有的字节累计没有重复计算IP头
	if (!pskb_pull(skb, skb_network_offset(skb) + ihl))
		goto err;
	// 截掉字节没有对齐的部分
	err = pskb_trim_rcsum(skb, end - offset);
	if (err)
		goto err;

	//当前分片是第一个分片或应放在当前skb队列最后
	prev = qp->q.fragments_tail;
	if (!prev || FRAG_CB(prev)->offset < offset) {
		next = NULL;
		goto found;
	}

	//根据offset偏移量找到当前分片在skb队列中的位置，应插入prev指针和next指针之间
	prev = NULL;
	for (next = qp->q.fragments; next != NULL; next = next->next) {
		if (FRAG_CB(next)->offset >= offset)
			break;	/* bingo! */
		prev = next;
	}

found:

	//检查新接收分片与应插入skb队列位置前后分片之间的是否存在数据重叠
	//如果出现重叠将队列偏后位置的分片重叠数据进行删除

	//若不是第一个分片则进入if语句
	if (prev) {

		//说明两个报文的负载有重叠，解决办法为将新收到的分片前面一部分删除
		int i = (FRAG_CB(prev)->offset + prev->len) - offset;

		if (i > 0) {
			offset += i;
			err = -EINVAL;
			//说明删除后本分片已经没有数据了
			if (end <= offset)
				goto err;
			err = -ENOMEM;
			//移动data指针，删除前i个字节
			if (!pskb_pull(skb, i))
				goto err;
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)
				skb->ip_summed = CHECKSUM_NONE;
		}
	}


	//循环向后检查新接收的分片与next数据是否有重叠
	while (next && FRAG_CB(next)->offset < end) {
		int i = end - FRAG_CB(next)->offset; 

		if (i < next->len) {
			//说明next末尾有一部分数据是没有重叠的，删除掉重叠的一部分
			if (!pskb_pull(next, i))
				goto err;
			FRAG_CB(next)->offset += i;
			qp->q.meat -= i;
			if (next->ip_summed != CHECKSUM_UNNECESSARY)
				next->ip_summed = CHECKSUM_NONE;
			break;
		} else {
			struct sk_buff *free_it = next;

			//next中所有字节都是重复的，删除next
			next = next->next;

			if (prev)
				prev->next = next;
			else
				qp->q.fragments = next;

			qp->q.meat -= free_it->len;
			sub_frag_mem_limit(qp->q.net, free_it->truesize);
			kfree_skb(free_it);
		}
	}

	FRAG_CB(skb)->offset = offset;

	//将新收到的分片插入到SKB队列中
	skb->next = next;
	if (!next)
		qp->q.fragments_tail = skb;
	if (prev)
		prev->next = skb;
	else
		qp->q.fragments = skb;


	//偏移量为0，说明是第一个分片，更新flags标志
	if (offset == 0)
		qp->q.flags |= INET_FRAG_FIRST_IN;


	// 所有片段都已经收到，重组IP报文
	if (qp->q.flags == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
	    qp->q.meat == qp->q.len) {
		unsigned long orefdst = skb->_skb_refdst;

		skb->_skb_refdst = 0UL;
		err = ip_frag_reasm(qp, prev, dev);
		skb->_skb_refdst = orefdst;
		return err;
	}
}
```
#### 2.2.5 所有分片均已收到重组ip报文 ip_frag_reasm()
```c

static int ip_frag_reasm(struct ipq *qp, struct sk_buff *prev,struct net_device *dev)
{
	struct net *net = container_of(qp->q.net, struct net, ipv4.frags);
	struct iphdr *iph;
	struct sk_buff *fp, *head = qp->q.fragments;
	int len;
	int ihlen;
	int err;
	u8 ecn;
	// 将IP分片队列从哈希表中摘下来，递减IP分片队列引用计数，以及停止相关定时器
	ipq_kill(qp);


	//使刚接收到的skb成为分片队列的头，完成重组后skb就是重组好的包。
	//ip_local_deliver函数最后向上层提交的包，就是最后到达的分片，需要将最后一个分片处理成重组好的包提交。
	
	if (prev) {
		head = prev->next;
		//skb_clone是浅拷贝，只克隆了skb结构体部分
		fp = skb_clone(head, GFP_ATOMIC);
		if (!fp)
			goto out_nomem;

		fp->next = head->next;
		if (!fp->next)
			qp->q.fragments_tail = fp;
		prev->next = fp;
		//同样进行了浅拷贝
		skb_morph(head, qp->q.fragments);
		head->next = qp->q.fragments->next;
		//释放了原来分片队列头的skb结构
		consume_skb(qp->q.fragments);
		qp->q.fragments = head;
	}

	// 计算整个IP报文的长度
	ihlen = ip_hdrlen(head);
	len = ihlen + qp->q.len;

	err = -E2BIG;
	// 整个IP报文长度不能超过65535字节
	if (len > 65535)
		goto out_oversize;

	// 第一个IP如果有片段部分，将片段部分先拿出来放到skb链表中之后再连接上，便于后面的操作
	if (skb_has_frag_list(head)) {
		struct sk_buff *clone;
		int i, plen = 0;

		clone = alloc_skb(0, GFP_ATOMIC);
		if (!clone)
			goto out_nomem;
		// 将clone插入到head之后
		clone->next = head->next;
		head->next = clone;
		// 将head的非线性区数据转移到clone的非线性区
		skb_shinfo(clone)->frag_list = skb_shinfo(head)->frag_list;
		skb_frag_list_init(head);
		for (i = 0; i < skb_shinfo(head)->nr_frags; i++)
			plen += skb_frag_size(&skb_shinfo(head)->frags[i]);
		//更新clone和head的相关长度字段
		clone->len = clone->data_len = head->data_len - plen;
		head->data_len -= clone->len;
		head->len -= clone->len;
		//重新计算clone的skb校验和
		clone->csum = 0;
		clone->ip_summed = head->ip_summed;
		add_frag_mem_limit(qp->q.net, clone->truesize);
	}

	// 将所有的IP分片链接到第一个IP片段的frag_list中
	skb_shinfo(head)->frag_list = head->next;
	skb_push(head, head->data - skb_network_header(head));

    //重新计算skb校验和以及长度信息
	for (fp=head->next; fp; fp = fp->next) {
		head->data_len += fp->len;
		head->len += fp->len;
		if (head->ip_summed != fp->ip_summed)
			head->ip_summed = CHECKSUM_NONE;
		else if (head->ip_summed == CHECKSUM_COMPLETE)
			head->csum = csum_add(head->csum, fp->csum);
		head->truesize += fp->truesize;
	}
}
```
***参考链接***
（1）https://blog.csdn.net/wangquan1992/article/details/109221056
（2）https://blog.csdn.net/wangquan1992/article/details/109228044
（3）https://blog.csdn.net/wangquan1992/article/details/109235276
（4）https://blog.csdn.net/wangpengqi/article/details/9276117