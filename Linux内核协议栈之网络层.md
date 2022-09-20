# Linux内核协议栈之网络层
***参考链接：***
https://www.cnblogs.com/jmilkfan-fanguiju/p/12789808.html
https://blog.csdn.net/wangquan1992/category_10378048_2.html

![linux协议栈示意图（初版）](https://github.com/zjc0000/story_images/raw/main/小书匠/1663650406600.png)
## 1 ipv4接收数据包流程
当设备接口层处理完输入数据包后，如果发现该报文应该由IP协议进一步处理，那么将会调用ip_rcv()函数。该接口完成对网络层数据包的校验和解析，之后通过netfilter模块和路由模块将处理后的数据包或转发或转给本机4层继续解析。核心流程如下：
（1）设备接口层处理完数据包后，调用ip_rcv()将数据包交由IP层继续处理；
（2）IP层首先做些简单的校验后，就尝试过 netfilter 的 PREROUTING 点；
（3）PREROUTING 点通过后，进行路由查询，决定是将数据包递交给本机，还是转发；
（4）对于递交给本机的数据包，过 LOCAL_IN 点，然后根据 IP 首部的协议字段，查找高层协议处理函数，然后调用该函数，将数据包交给高层协议继续处理；
（5）对于需要转发的数据包，根据转发的需要，修改IP首部内容（TTL），然后过FORWARD点，最后走和本机发送数据包一样的流程将数据包转发出去。

主要涉及如下文件：
net/ipv4/ip_input.c	IP协议输入报文处理过程
net/ipv4/ip_forward.c	IP协议转发报文处理过程
### 1.1 ip_rcv()
完成IP报文基本的校验和处理工作：
（1）丢弃PACKET_OTHERHOST类型的包
（2）校验ip头的长度和版本，校验skb长度、ip头长度以及ip包总长度
（3）对IP头进行校验和验证
```c
@skb: 数据包
@dev：数据包的当前输入网络设备（层二可能会使用一些聚合技术）
@pt：数据包的类型
@orig_dev: 接收数据包的原始网络设备
int ip_rcv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	struct iphdr *iph;
	u32 len;
 
	if (dev->nd_net != &init_net)
		goto drop;
 
	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
    // 在混杂模式下，发往其它主机的一些数据包有可能会到达这里，IPv4并不关注这种包，忽略它们
    //skb->pkt_type 在 eth_type_trans()函数中设置。
	// 注意：需要本机转发的包目的MAC地址就是本机接口地址，目的IP地址才是远端IP地址
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;
 
	IP_INC_STATS_BH(IPSTATS_MIB_INRECEIVES);
	// 因为后面可能会修改SKB描述符的内容，所以如果该SKB描述符是被共享的(其users成员不为1)，
    // 那么复制一个新的，然后返回，后面的接收处理过程都是用该新的SKB
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
		IP_INC_STATS_BH(IPSTATS_MIB_INDISCARDS);
		goto out;
	}
	// 确保skb线性区域中至少有IP首部长度个字节的数据
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;
	// pskb_may_pull()可能会调整内存，所以iph需要重新指向
	iph = ip_hdr(skb);
 
	/*
	 *	RFC1122: 3.1.2.2 MUST silently discard any IP frame that fails the checksum.
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
	// 这里之所以又做一遍，是因为IP首部可能还有选项部分,iph->ihl*4是IP报文的真实首部长度
	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;
	// 同上，SKB内部指针可能已经发生变化，所以iph需要重新指向
	iph = ip_hdr(skb);
	// 检查IP首部的校验和，确保接收数据传输无误
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto inhdr_error;
	
    // 校验IP数据包的总长度
	len = ntohs(iph->tot_len);
	if (skb->len < len) {
		IP_INC_STATS_BH(IPSTATS_MIB_INTRUNCATEDPKTS);
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
		IP_INC_STATS_BH(IPSTATS_MIB_INDISCARDS);
		goto drop;
	}
 
	// 将IP控制块内容全部清零，后面IP层处理过程中会使用该控制块数据结构
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	// 数据包进入PREROUTING链，如果通过该链，则将数据包传递给ip_rcv_finish()继续处理
	return NF_HOOK(PF_INET, NF_INET_PRE_ROUTING, skb, dev, NULL, ip_rcv_finish);
 
inhdr_error:
	IP_INC_STATS_BH(IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}
```
### 1.2 PRE_ROUTING钩子点
根据钩子函数注册源码可以看出在相同优先级情况下，后注册的钩子反而在先注册钩子的前面。
钩子点完成什么工作?

### 1.3 ip_rcv_finish()
查找路由确定报文时分发出去还是传给上层继续解析：
（1）数据包已经填充好skb_dst(skb)->input字段则直接调用
（2）否则调用ip_route_input_noref函数为其查找并填充，往本地协议栈上传就填充 ip_local_deliver，转发就填充ip_forward 
问题：
（1）如果数据包已经填充好是什么时候填充的？
（2）ip_route_input_noref填充原理？
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

	/*
	 * 如果该报文的路由缓存无效，则调用ip_route_input_noref函数为其查找，如果查找失败则丢弃该报文
	 * 查找成功则填充好skb_dst(skb)->input字段（ip_forward或是ip_local_deliver）
	 * 问题：如果有效是什么时候填充的？ip_route_input_noref填充原理？
	*/

	if (!skb_valid_dst(skb)) {
		err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
					   iph->tos, dev);
		if (unlikely(err))
			goto drop_error;
	}

	// 如果该数据包包含IP选项，则解析这些选项并进行一定的处理
	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	// 根据目的路由信息，如果需要，更新多播和广播统计
	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST) {
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST) {
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INBCAST, skb->len);
	} else if (skb->pkt_type == PACKET_BROADCAST ||
		   skb->pkt_type == PACKET_MULTICAST) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev &&
		    IN_DEV_ORCONF(in_dev, DROP_UNICAST_IN_L2_MULTICAST))
			goto drop;
	}

	/*
	 * 实际是调用存放在skb->dst->input的数据域。
	 * 数据包已经填充好相关字段数据包或是由ip_route_input_noref函数填充
	 * 可能是往本地协议栈上传就调用 ip_local_deliver，如果是转发就调用ip_forward 
	*/
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

### 1.4 dst_input()
实际上调用skb_dst(skb)->input字段，往本地协议栈上传就调用 ip_local_deliver，如果是转发就调用ip_forward 
```c
/* Input packet from network to transport.  */
static inline int dst_input(struct sk_buff *skb)
{
	//往本地协议栈上传就调用 ip_local_deliver，如果是转发就调用ip_forward 
	//调用skb中的目的路由信息中的input()继续处理，SKB中的dst信息实际上就是前面的ip_route_input()查询
	return skb_dst(skb)->input(skb);
}
```

### 1.5 ip_local_deliver()
完成IP数据包的分片重组工作
```c
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	struct net *net = dev_net(skb->dev);

	//判断数据包是否为一个分组
	if (ip_is_fragment(ip_hdr(skb))) {
		//进行分片重组，ip_defrag成功返回0，skb就是重组的包，进入LOCAL_IN钩子点
		//ip_local_deliver函数最后向上层提交的包，就是最后到达的分片，需要将最后一个分片处理成重组好的包提交。
		if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}

	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
		       net, NULL, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}
```
### 1.6 LOCAL_IN钩子点



### 1.7 ip_local_deliver_finish()
协议栈的原始套接字从实现上可以分为“链路层原始套接字”和“网络层原始套接字”两大类。



