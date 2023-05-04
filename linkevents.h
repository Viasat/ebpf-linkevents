/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Viasat */
#ifndef __LINKEVENTS_H
#define __LINKEVENTS_H

#define IFNAMSIZ 16 // uapi/linux/if.h

struct event_t {
	__u32         pid;
	__u64         ts;
	int           source; // 0 -> link, 1 -> addr
	int           type;
	char          name[IFNAMSIZ];
	int           ifindex;
	unsigned int  flags;
	unsigned char dev_addr[6];
	__be32        ifa_address;
	unsigned int  nsid;
};

#endif /* __LINKEVENTS_H */
