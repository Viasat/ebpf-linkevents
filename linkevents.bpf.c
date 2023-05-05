/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 Viasat */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "linkevents.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static int __rtmsg_ifinfo_build_skb(void *ctx, int source,
				    int type, struct net_device *dev,
				    struct in_ifaddr *ifa)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();
	struct event_t event = {};

	event.pid = pid;
	event.ts = ts;
	event.source = source;
	event.type = type;

	if (ifa) {
		struct in_device *ifa_dev;
		bpf_core_read(&ifa_dev, sizeof(void *), &ifa->ifa_dev);
		bpf_core_read(&dev, sizeof(void *), &ifa_dev->dev);

		bpf_core_read(&event.ifa_address, sizeof(event.ifa_address), &ifa->ifa_address);
	}

	bpf_core_read_str(event.name, sizeof(event.name), &dev->name);
	bpf_core_read(&event.ifindex, sizeof(event.ifindex), &dev->ifindex);
	bpf_core_read(&event.flags, sizeof(event.flags), &dev->flags);

	unsigned char *dev_addr;
	bpf_core_read(&dev_addr, sizeof(void *), &dev->dev_addr);
	bpf_core_read(event.dev_addr, sizeof(event.dev_addr), dev_addr);

	event.nsid = BPF_CORE_READ(dev, nd_net.net, ns.inum);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

// https://elixir.bootlin.com/linux/v5.14.21/source/net/core/rtnetlink.c#L3802
SEC("fentry/rtmsg_ifinfo_build_skb")
int BPF_PROG(fentry_rtmsg_ifinfo_build_skb,
	     int type, struct net_device *dev)
{
	//bpf_printk("fentry_rtmsg_ifinfo_build_skb entered\n");
	return __rtmsg_ifinfo_build_skb(ctx, 0, type, dev, NULL);
}

SEC("kprobe/rtmsg_ifinfo_build_skb")
int BPF_KPROBE(kprobe_rtmsg_ifinfo_build_skb,
	       int type, struct net_device *dev)
{
	//bpf_printk("kprobe_rtmsg_ifinfo_build_skb entered\n");
	return __rtmsg_ifinfo_build_skb(ctx, 0, type, dev, NULL);
}

// https://elixir.bootlin.com/linux/v5.14.21/source/net/ipv4/devinet.c#L1884
SEC("fentry/rtmsg_ifa")
int BPF_PROG(fentry_rtmsg_ifa,
	     int type, struct in_ifaddr *ifa)
{
	//bpf_printk("fentry_rtmsg_ifa entered\n");
	return __rtmsg_ifinfo_build_skb(ctx, 1, type, NULL, ifa);
}

SEC("kprobe/rtmsg_ifa")
int BPF_KPROBE(kprobe_rtmsg_ifa,
	       int type, struct in_ifaddr *ifa)
{
	//bpf_printk("kprobe_rtmsg_ifa entered\n");
	return __rtmsg_ifinfo_build_skb(ctx, 1, type, NULL, ifa);
}

char LICENSE[] SEC("license") = "GPL";
