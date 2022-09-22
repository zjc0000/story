# Linux内核协议栈之网络层

[toc]
## 1.网络层协议整体流程图


![网络层协议栈整体流程图](https://github.com/zjc0000/story_images/raw/main/小书匠/1663812594329.png)

## 2.IPv4发送数据包流程
### 2.1 上层发送接口
IP层对外提供了多个发送接口，高层协议会根据需要进行调用。发送接口处理完毕后，都会调用ip_local_out()进行报文发送。

**对于TCP协议：**
（1）ip_queue_xmit函数是ip层提供给tcp层发送回调，大多数tcp发送都会使用这个回调，tcp层使用tcp_transmit_skb封装了tcp头之后，调用该函数，该函数提供了路由查找校验、封装ip头和ip选项的功能，封装完成之后调用ip_local_out发送数据包；
（2）ip_build_and_send_pkt函数是服务器端在给客户端回复syn+ack时调用的，该函数在构造ip头之后，调用ip_local_out发送数据包；
（3）ip_send_unicast_reply函数目前只用于发送ACK和RST，该函数根据对端发过来的skb构造ip头，然后调用ip_append_data向发送队列中附加/新增数据，ip_push_pending_frames函数->ip_send_skb函数-> ip_local_out函数。

**对于UDP协议：**
udp_push_pending_frames函数->ip_push_pending_frames函数->ip_send_skb函数-> ip_local_out函数

**对于ICMP协议：**
icmp_send函数-> icmp_push_reply函数->ip_push_pending_frames函数->ip_send_skb函数-> ip_local_out函数

#### 2.1.1 ip_queue_xmit()
```c
int ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ip_options_rcu *inet_opt;
	struct flowi4 *fl4;
	struct rtable *rt;
	struct iphdr *iph;
	int res;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
	rcu_read_lock();
	inet_opt = rcu_dereference(inet->inet_opt);
	fl4 = &fl->u.ip4;
	// 获取skb中的路由缓存 
	rt = skb_rtable(skb);
	 // skb中有缓存则跳转处理
	if (rt)
		goto packet_routed;

	/* Make sure we can route this packet. */
	//检查控制块中的路由缓存 
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	// 缓存过期
	if (!rt) {
		__be32 daddr;

		/* Use correct destination address if we have options. */
		daddr = inet->inet_daddr;
		if (inet_opt && inet_opt->opt.srr)
			daddr = inet_opt->opt.faddr;

		/* If this fails, retransmit mechanism of transport layer will
		 * keep trying until route appears or the connection times
		 * itself out.
		 */
		 //查找路由缓存 ,填充好skb->dst->output接口供dst_output函数调用
		rt = ip_route_output_ports(net, fl4, sk,
					   daddr, inet->inet_saddr,
					   inet->inet_dport,
					   inet->inet_sport,
					   sk->sk_protocol,
					   RT_CONN_FLAGS(sk),
					   sk->sk_bound_dev_if);
		if (IS_ERR(rt))
			goto no_route;
		sk_setup_caps(sk, &rt->dst);
	}
	skb_dst_set_noref(skb, &rt->dst);

packet_routed:
	if (inet_opt && inet_opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto no_route;

	/* OK, we know where to send it, allocate and build IP header. */
	//分配空间并填充IP头
	skb_push(skb, sizeof(struct iphdr) + (inet_opt ? inet_opt->opt.optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (inet->tos & 0xff));
	if (ip_dont_fragment(sk, &rt->dst) && !skb->ignore_df)
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->dst);
	iph->protocol = sk->sk_protocol;
	ip_copy_addrs(iph, fl4);

	/* Transport layer set skb->h.foo itself. */
	// 构造ip选项 
	if (inet_opt && inet_opt->opt.optlen) {
		iph->ihl += inet_opt->opt.optlen >> 2;
		ip_options_build(skb, &inet_opt->opt, inet->inet_daddr, rt, 0);
	}

	ip_select_ident_segs(net, skb, sk,
			     skb_shinfo(skb)->gso_segs ?: 1);

	/* TODO : should we use skb->sk here instead of sk ? */
	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;
	//调用ip_local_out输出
	res = ip_local_out(net, sk, skb);
	rcu_read_unlock();
	return res;

no_route:
	rcu_read_unlock();
	IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
	kfree_skb(skb);
	return -EHOSTUNREACH;
}
```
#### 2.1.2 ip_build_and_send_pkt()
```c
int ip_build_and_send_pkt(struct sk_buff *skb, const struct sock *sk,
			  __be32 saddr, __be32 daddr, struct ip_options_rcu *opt)
{
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = skb_rtable(skb);
	struct net *net = sock_net(sk);
	struct iphdr *iph;

	/* Build the IP header. */
	skb_push(skb, sizeof(struct iphdr) + (opt ? opt->opt.optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	iph->version  = 4;
	iph->ihl      = 5;
	iph->tos      = inet->tos;
	iph->ttl      = ip_select_ttl(inet, &rt->dst);
	iph->daddr    = (opt && opt->opt.srr ? opt->opt.faddr : daddr);
	iph->saddr    = saddr;
	iph->protocol = sk->sk_protocol;
	if (ip_dont_fragment(sk, &rt->dst)) {
		iph->frag_off = htons(IP_DF);
		iph->id = 0;
	} else {
		iph->frag_off = 0;
		__ip_select_ident(net, iph, 1);
	}

	if (opt && opt->opt.optlen) {
		iph->ihl += opt->opt.optlen>>2;
		ip_options_build(skb, &opt->opt, daddr, rt, 0);
	}

	skb->priority = sk->sk_priority;
	if (!skb->mark)
		skb->mark = sk->sk_mark;

	/* Send it out. */
	return ip_local_out(net, skb->sk, skb);
}
```
#### 2.1.3 ip_send_unicast_reply()
```c
void ip_send_unicast_reply(struct sock *sk, struct sk_buff *skb,
               const struct ip_options *sopt,
               __be32 daddr, __be32 saddr,
               const struct ip_reply_arg *arg,
               unsigned int len)
{
    struct ip_options_data replyopts;
    struct ipcm_cookie ipc;
    struct flowi4 fl4;
    struct rtable *rt = skb_rtable(skb);
    struct net *net = sock_net(sk);
    struct sk_buff *nskb;
    int err;
    int oif;

    /* 获取ip选项 */
    if (__ip_options_echo(&replyopts.opt.opt, skb, sopt))
        return;

    ipc.addr = daddr;
    ipc.opt = NULL;
    ipc.tx_flags = 0;
    ipc.ttl = 0;
    ipc.tos = -1;

    /* 选项存在 */
    if (replyopts.opt.opt.optlen) {
        ipc.opt = &replyopts.opt;

        /* 源路由存在，设置下一跳ip地址为目的地址 */
        if (replyopts.opt.opt.srr)
            daddr = replyopts.opt.opt.faddr;
    }

    /* 输出接口设置 */
    oif = arg->bound_dev_if;
    if (!oif && netif_index_is_l3_master(net, skb->skb_iif))
        oif = skb->skb_iif;

    /* 查路由 */
    flowi4_init_output(&fl4, oif,
               IP4_REPLY_MARK(net, skb->mark),
               RT_TOS(arg->tos),
               RT_SCOPE_UNIVERSE, ip_hdr(skb)->protocol,
               ip_reply_arg_flowi_flags(arg),
               daddr, saddr,
               tcp_hdr(skb)->source, tcp_hdr(skb)->dest,
               arg->uid);
    security_skb_classify_flow(skb, flowi4_to_flowi(&fl4));
    rt = ip_route_output_key(net, &fl4);
    if (IS_ERR(rt))
        return;


    /* 根据skb更新sk的属性 */
    inet_sk(sk)->tos = arg->tos;

    sk->sk_priority = skb->priority;
    sk->sk_protocol = ip_hdr(skb)->protocol;
    sk->sk_bound_dev_if = arg->bound_dev_if;
    sk->sk_sndbuf = sysctl_wmem_default;
    sk->sk_mark = fl4.flowi4_mark;
    /* 数据追加到前一个skb或者新建skb后添加到发送队列 */
    err = ip_append_data(sk, &fl4, ip_reply_glue_bits, arg->iov->iov_base,
                 len, 0, &ipc, &rt, MSG_DONTWAIT);
    if (unlikely(err)) {
        ip_flush_pending_frames(sk);
        goto out;
    }

    /* 如果发送队列有skb，则计算校验和，发送 */
    nskb = skb_peek(&sk->sk_write_queue);
    if (nskb) {
        if (arg->csumoffset >= 0)
            *((__sum16 *)skb_transport_header(nskb) +
              arg->csumoffset) = csum_fold(csum_add(nskb->csum,
                                arg->csum));
        nskb->ip_summed = CHECKSUM_NONE;

        /* 发送数据包 */
        ip_push_pending_frames(sk, &fl4);
    }
out:
    ip_rt_put(rt);
}
```
#### 2.1.4 ip_push_pending_frames()
```c

```
#### 2.1.5 ip_send_skb()
```c
int ip_send_skb(struct net *net, struct sk_buff *skb)
{
        int err;
        err = ip_local_out(skb);
		//如果调用失败，就更新相应的错误计数
        if (err) {
                if (err > 0)
                        err = net_xmit_errno(err);
                if (err)
                        IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
        }
        return err;
}
```

### 2.2 ip_local_out()
```c
int ip_local_out(struct sk_buff *skb)
{
	int err;
 
	err = __ip_local_out(skb);
	if (likely(err == 1))
		err = dst_output(skb);
	return err;
}
 
int __ip_local_out(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
 	//设置IP头部总长度字段
	iph->tot_len = htons(skb->len);
	//校验和相关处理
	ip_send_check(iph);
	
		/* if egress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip_out(sk, skb);
	if (unlikely(!skb))
		return 0;
		
	//设置skb->protocal字段为IP协议
	skb->protocol = htons(ETH_P_IP);
	
	//过LOCAL_OUT点，通过后调用dst_output()
	return nf_hook(PF_INET, NF_INET_LOCAL_OUT, skb, NULL, skb->dst->dev,
		       dst_output);
}
```
### 2.3 dst_output()
这里实际上会调用路由查询结果中的output(),在之前查找路由后会进行填充。
```c
/* Output packet to network from transport.  */
static inline int dst_output(struct sk_buff *skb)
{
   /*
     * 如果是单播数据包，设置的是ip_output(),
     * 如果是组播数据包，设置的是ip_mc_output().dev_queue_xmit
     */
	return skb->dst->output(skb);
}
```
### 2.4 ip_output()
```c
int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb_dst(skb)->dev;

	IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);
	//设置输出设备
	skb->dev = dev;
	//设置skb->protocal字段为IP协议
	skb->protocol = htons(ETH_P_IP);

	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING,
			    net, sk, skb, NULL, dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}
```
### 2.5 ip_finish_output()
```c
static int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	unsigned int mtu;
	int ret;

	ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
	if (ret) {
		kfree_skb(skb);
		return ret;
	}
	//获取mtu
	mtu = ip_skb_dst_mtu(sk, skb);
	
	//gso是一种利用网卡对数据包分片，减轻CPU负荷的一种技术，与之对应的接收技术是gro，都是通过减少数据包通过协议栈的次数来降低CPU负担
	//开启了gso选项，则调用gso输出 ,最终调用还是ip_finish_output2
	if (skb_is_gso(skb))
		return ip_finish_output_gso(net, sk, skb, mtu);
	//若没有开启gso且包长大于mtu，则需进行分片后再输出
	if (skb->len > mtu || (IPCB(skb)->flags & IPSKB_FRAG_PMTU))
		return ip_fragment(net, sk, skb, mtu, ip_finish_output2);
	//不需分片直接输出
	return ip_finish_output2(net, sk, skb);
}
```
### 2.6 ip_finish_output2()
```c
static int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);
	struct neighbour *neigh;
	u32 nexthop;

	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS(net, IPSTATS_MIB_OUTBCAST, skb->len);

	//如果skb的头部不足以容纳L2的报头，那么重新构造新的skb调整头部空间，并且释放旧的skb
	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		struct sk_buff *skb2;
		
		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (!skb2) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		// 重新关联与该skb相关的socket结构
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
			
		consume_skb(skb);
		skb = skb2;
	}

	if (lwtunnel_xmit_redirect(dst->lwtstate)) {
		int res = lwtunnel_xmit(skb);

		if (res < 0 || res == LWTUNNEL_XMIT_DONE)
			return res;
	}

	rcu_read_lock_bh();
	//获取下一跳
	nexthop = (__force u32) rt_nexthop(rt, ip_hdr(skb)->daddr);
	// 获取邻居子系统
	neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
	// 获取失败，则创建邻居子系统
	if (unlikely(!neigh))
		neigh = __neigh_create(&arp_tbl, &nexthop, dev, false);
	if (!IS_ERR(neigh)) {
		int res;
		// 更新路由缓存确认
		sock_confirm_neigh(skb, neigh);
		//通过邻居子系统输出
		res = neigh_output(neigh, skb);
		rcu_read_unlock_bh();
		return res;
	}
	rcu_read_unlock_bh();

	net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
			    __func__);
	kfree_skb(skb);
	return -EINVAL;
}
```
## 3.IPv4接收数据包流程
当设备接口层处理完输入数据包后，如果发现该报文应该由IP协议进一步处理，那么将会调用ip_rcv()函数。该接口完成对网络层数据包的校验和解析，之后通过netfilter模块和路由模块将处理后的数据包或转发或转给本机4层继续解析。核心流程如下：
（1）设备接口层处理完数据包后，调用ip_rcv()将数据包交由IP层继续处理；
（2）IP层首先做些简单的校验后，就尝试过 netfilter 的 PREROUTING 点；
（3）PREROUTING 点通过后，进行路由查询，决定是将数据包递交给本机，还是转发；
（4）对于递交给本机的数据包，过 LOCAL_IN 点，然后根据 IP 首部的协议字段，查找高层协议处理函数，然后调用该函数，将数据包交给高层协议继续处理；
（5）对于需要转发的数据包，根据转发的需要，修改IP首部内容（TTL），然后过FORWARD点，最后走和本机发送数据包一样的流程将数据包转发出去。

### 3.1 ip_rcv()
```c
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct iphdr *iph;
	struct net *net;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	// 在混杂模式下，发往其它主机的一些数据包有可能会到达这里，IPv4并不关注这种包，忽略它们
    // skb->pkt_type 在 eth_type_trans()函数中设置。 
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;


	net = dev_net(dev);
	__IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);
	// 因为后面可能会修改SKB描述符的内容，所以如果该SKB描述符是被共享的(其users成员不为1)，
    // 那么复制一个新的，然后返回，后面的接收处理过程都是用该新的SKB
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto out;
	}
	
	// 确保skb线性区域中至少有IP首部长度个字节的数据
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;
	// pskb_may_pull()可能会调整内存，所以iph需要重新指向
	iph = ip_hdr(skb);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */
	// 1&2：检查首部长度和IP协议版本号
	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;

	BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
	BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
	BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
	__IP_ADD_STATS(net,
		       IPSTATS_MIB_NOECTPKTS + (iph->tos & INET_ECN_MASK),
		       max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;
	iph = ip_hdr(skb);
	
	// 检查IP首部的校验和，确保接收数据传输无误
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto csum_error;
	
	// 校验IP数据包的总长度
	len = ntohs(iph->tot_len);
	if (skb->len < len) {
		__IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < (iph->ihl*4))
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	 
	// 如注释所述，层二有可能会在IP数据包上打padding，所这里知道了IP数据包的总长度，
    // 需要对SKB的长度字段进行调整并重新计算校验和
	if (pskb_trim_rcsum(skb, len)) {
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	skb->transport_header = skb->network_header + iph->ihl*4;

	// 将IP控制块内容全部清零，后面IP层处理过程中会使用该控制块数据结构
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	IPCB(skb)->iif = skb->skb_iif;

	/* Must drop socket now because of tproxy. */
	skb_orphan(skb);
	// 数据包进入PREROUTING链，如果通过该链，则将数据包传递给ip_rcv_finish()继续处理
	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip_rcv_finish);

csum_error:
	__IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
inhdr_error:
	__IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}
```
### 3.2 ip_rcv_finish()
```c
static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	int (*edemux)(struct sk_buff *skb);
	struct net_device *dev = skb->dev;
	struct rtable *rt;
	int err;

	/* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip_rcv(skb);
	if (!skb)
		return NET_RX_SUCCESS;

	if (net->ipv4.sysctl_ip_early_demux &&
	    !skb_dst(skb) &&
	    !skb->sk &&
	    !ip_is_fragment(iph)) {
		const struct net_protocol *ipprot;
		int protocol = iph->protocol;

		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot && (edemux = READ_ONCE(ipprot->early_demux))) {
			err = edemux(skb);
			if (unlikely(err))
				goto drop_error;
			/* must reload iph, skb->head might have changed */
			iph = ip_hdr(skb);
		}
	}

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	// 如果数据包还没有目的路由，则通过路由子系统的ip_route_input_noref()查询路由，
    // 进而决定该数据包的去向
	if (!skb_valid_dst(skb)) {
		err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
					   iph->tos, dev);
		if (unlikely(err))
			goto drop_error;
	}

#ifdef CONFIG_IP_ROUTE_CLASSID
	if (unlikely(skb_dst(skb)->tclassid)) {
		struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
		u32 idx = skb_dst(skb)->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes += skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes += skb->len;
	}
#endif

	// 如果该数据包包含IP选项，则解析这些选项并进行一定的处理
	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST) {
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST) {
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INBCAST, skb->len);
	} else if (skb->pkt_type == PACKET_BROADCAST ||
		   skb->pkt_type == PACKET_MULTICAST) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		/* RFC 1122 3.3.6:
		 *
		 *   When a host sends a datagram to a link-layer broadcast
		 *   address, the IP destination address MUST be a legal IP
		 *   broadcast or IP multicast address.
		 *
		 *   A host SHOULD silently discard a datagram that is received
		 *   via a link-layer broadcast (see Section 2.4) but does not
		 *   specify an IP multicast or broadcast destination address.
		 *
		 * This doesn't explicitly say L2 *broadcast*, but broadcast is
		 * in a way a form of multicast and the most common use case for
		 * this is 802.11 protecting against cross-station spoofing (the
		 * so-called "hole-196" attack) so do it for both.
		 */
		if (in_dev &&
		    IN_DEV_ORCONF(in_dev, DROP_UNICAST_IN_L2_MULTICAST))
			goto drop;
	}
	// 根据目的路由进行向上分发，或者是转发
	return dst_input(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;

drop_error:
	if (err == -EXDEV)
		__NET_INC_STATS(net, LINUX_MIB_IPRPFILTER);
	goto drop;
}
```

### 3.3 dst_input()
实际上调用skb_dst(skb)->input字段，往本地协议栈上传就调用 ip_local_deliver，如果是转发就调用ip_forward 
```c
/* Input packet from network to transport.  */
static inline int dst_input(struct sk_buff *skb)
{
    // 调用skb中的目的路由信息中的input()继续处理，SKB中的dst信息实际上就是前面的ip_route_input()查询
    // 路由表时设置好的，所以说，查询路由表就是要获取一个dst信息并将其设置到skb中
	return skb_dst(skb)->input(skb);
}
```

### 3.4 ip_local_deliver()
完成IP数据包的分片重组工作
```c
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	struct net *net = dev_net(skb->dev);
	
	// 首先检查该IP数据报是否是分片，如果是则要调用ip_defrag()尝试进行组装，组装成功则继续处理，
    // 否则需要先进行缓存等待其它分组的到达
	if (ip_is_fragment(ip_hdr(skb))) {
		if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}
	// 进入LOCAL_IN HOOK点,如果通过则调用ip_local_deliver_finish()继续处理
	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
		       net, NULL, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}
```

### 3.5 ip_local_deliver_finish()
```c
static int ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	// 在skb中将IP首部删掉
	__skb_pull(skb, skb_network_header_len(skb));

	rcu_read_lock();
	{
		// 取出IP首部的协议字段，根据该字段寻找对应的上层协议
		int protocol = ip_hdr(skb)->protocol;
		const struct net_protocol *ipprot;
		int raw;

	resubmit:
		//创建面向连接的TCP和创建面向无连接的UDP套接字，在接收和发送时只能操作数据部分，而不能对IP首部或TCP和UDP首部进行操作。如果想要操作IP首部或传输层协议首部，就需要创建网络层原始套接字
		// 网络层 RAW 套接字处理，若匹配上就通过 skb_clone() 克隆报文并交给相应的原始套接字来处理
		// 注意：这里只是将报文克隆一份交给原始套接字，而该报文还是会继续走后续的协议栈处理流程。
		//ref:https://blog.csdn.net/wangquan1992/article/details/112787536
		raw = raw_local_deliver(skb, protocol);
		
		// 从inet_protos数组中寻找上层协议提供的接收处理回调
		// 在协议族初始化时,所有的上层协议都会将自己的接收处理接口注册到该数组中
		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot) {
			int ret;

			if (!ipprot->no_policy) {
				if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					kfree_skb(skb);
					goto out;
				}
				nf_reset(skb);
			}
			// 调用传输层接口处理
			ret = ipprot->handler(skb);
			// 如果上层的处理返回错误，这里会将错误码作为协议号，重新执行上述流程
			if (ret < 0) {
				protocol = -ret;
				goto resubmit;
			}
			__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
		} else {
			if (!raw) {
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					__IP_INC_STATS(net, IPSTATS_MIB_INUNKNOWNPROTOS);
					//没有对应的上层协议，发送ICMP不可达报文
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
				kfree_skb(skb);
			} else {
				__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
				consume_skb(skb);
			}
		}
	}
 out:
	rcu_read_unlock();

	return 0;
}
}
```

## 4.IPv4转发数据包流程
### 4.1 ip_forward()
```c
int ip_forward(struct sk_buff *skb)
{
	u32 mtu;
	struct iphdr *iph;	/* Our header */
	struct rtable *rt;	/* Route we use */
	struct ip_options *opt	= &(IPCB(skb)->opt);
	struct net *net;

	/* that should never happen */
	// 确保该数据包确实是让自己转发的
	if (skb->pkt_type != PACKET_HOST)
		goto drop;

	if (unlikely(skb->sk))
		goto drop;

	if (skb_warn_if_lro(skb))
		goto drop;

	if (!xfrm4_policy_check(NULL, XFRM_POLICY_FWD, skb))
		goto drop;

	if (IPCB(skb)->opt.router_alert && ip_call_ra_chain(skb))
		return NET_RX_SUCCESS;

	// 转发会修改IP的首部字段，所以需要把检验和设置为CHECKSUM_NONE重新校验
	skb_forward_csum(skb);
	net = dev_net(skb->dev);

	/*
	 *	According to the RFC, we must first decrease the TTL field. If
	 *	that reaches zero, we must reply an ICMP control message telling
	 *	that the packet's lifetime expired.
	 */
	 // 如果TTL已经减为1，那么向发送段回复生命周期太短的ICMP报文
	if (ip_hdr(skb)->ttl <= 1)
		goto too_many_hops;

	if (!xfrm4_route_forward(skb))
		goto drop;

	// 严格源路由选项检查
	rt = skb_rtable(skb);

	if (opt->is_strictroute && rt->rt_uses_gateway)
		goto sr_failed;

	// IP分片相关处理，mtu过大不能转发，发送需要分片的icmp错误报文
	IPCB(skb)->flags |= IPSKB_FORWARDED;
	mtu = ip_dst_mtu_maybe_forward(&rt->dst, true);
	if (ip_exceeds_mtu(skb, mtu)) {
		IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(mtu));
		goto drop;
	}

	/* We are about to mangle packet. Copy it! */
	if (skb_cow(skb, LL_RESERVED_SPACE(rt->dst.dev)+rt->dst.header_len))
		goto drop;
	iph = ip_hdr(skb);

	/* Decrease ttl after skb cow done */
	//递减TTL
	ip_decrease_ttl(iph);

	/*
	 *	We now generate an ICMP HOST REDIRECT giving the route
	 *	we calculated.
	 */
	  // 关于路由重定向选项处理
	if (IPCB(skb)->flags & IPSKB_DOREDIRECT && !opt->srr &&
	    !skb_sec_path(skb))
		ip_rt_send_redirect(skb);

	// 根据TOS字段转换出优先级
	skb->priority = rt_tos2priority(iph->tos);
	
	// 进入FORWARD链，如果通过调用ip_forward_finish()完成转发过程处理
	return NF_HOOK(NFPROTO_IPV4, NF_INET_FORWARD,
		       net, NULL, skb, skb->dev, rt->dst.dev,
		       ip_forward_finish);

sr_failed:
	/*
	 *	Strict routing permits no gatewaying
	 */
	 icmp_send(skb, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
	 goto drop;

too_many_hops:
	/* Tell the sender its packet died... */
	__IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
	icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}
```

### 4.2 ip_forward_finish()
```c
static int ip_forward_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct ip_options *opt	= &(IPCB(skb)->opt);

	__IP_INC_STATS(net, IPSTATS_MIB_OUTFORWDATAGRAMS);
	__IP_ADD_STATS(net, IPSTATS_MIB_OUTOCTETS, skb->len);
	// 处理IP转发选项
	if (unlikely(opt->optlen))
		ip_forward_options(skb);
	// 直接调用路由输出，指向的应该是单播ip_output()或者组播ip_mc_output()
	return dst_output(net, sk, skb);
}
```

***整理来源：***
https://blog.csdn.net/wangquan1992/article/details/109188604
https://blog.csdn.net/wangquan1992/article/details/109196476