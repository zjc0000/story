# Linux内核对IP分片重组的详细解析
## 1 IP分片重组控制信息数据结构
### 1.1 网络命名空间struct netns_ipv4
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
### 1.2 IPV4协议用于分片重组的全局哈希表信息 struct inet_frags
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
### 1.3 IP分片队列 struct ipq [struct inet_frag_queue]
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
### 1.4 上述数据结构之间的关系

![IP分片重组数据结构](https://github.com/zjc0000/story_images/raw/main/小书匠/1663649025103.png)
## 2 IP分片重组完整流程
### 2.1 IP片段接收入口ip_local_deliver()
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
 ### 2.2 IP片段重组 ip_defrag()
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
 ### 2.3 查找IP分片队列 ip_find()
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
### 2.4 重组IP报文 ip_frag_queue()
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
### 2.5 所有分片均已收到重组ip报文 ip_frag_reasm()
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
（1）https://blog.csdn.net/wangquan1992/article/details/109228044
（2）https://blog.csdn.net/wangquan1992/article/details/109235276
（3）https://blog.csdn.net/wangpengqi/article/details/9276117