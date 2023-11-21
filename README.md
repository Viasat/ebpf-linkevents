# ebpf linkevents monitor

A small eBPF program that monitors/reports link and address events
across all network namespaces.

## Motivation

The standard mechanism for monitoring interface events in other
network namespaces is to open a netlink socket (`AF_NETLINK`) and then
set the `NETLINK_LISTEN_ALL_NSID` property on the socket. However,
this will only show events for containers that have some sort of
connection (e.g. veth pair) back to the network namespace where the
netlink socket was created. Using an small eBPF program we can insert
kprobes into the kernel to monitor events from all network namespaces
regardless of whether they have any connection to the network
namespace where the listener is running.


## Usage

* Build docker image

```
docker build -t ebpf-linkevents .
```

* Run docker image

```
docker run -it --cap-add sys_admin --cap-add sys_resource ebpf-linkevents /usr/bin/linkevents
```

* In another terminal, create a container with a standalone namespace
  and create a dummy interface in it:

```
docker run -it --network none --cap-add net_admin alpine ip link add dummy0 type dummy
```

The monitor will show all link and address activity in that container.
This will include the create/deletion of general interfaces like `lo`
in addition to the `dummy0` link.

## Links

* https://github.com/iovisor/bpftrace
* [https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
* https://nakryiko.com/posts/libbpf-bootstrap/
* https://nakryiko.com/posts/bpf-core-reference-guide/

## Copyright & License

This software is copyright Viasat, Inc. The kernel eBPF code is
released under the terms of the GPL-2.0 license and other code is
released under either the LGPL-2.1 OR BSD-2-Clause licenses. A copy of
the licenses are located in the the files LICENSE (GPL-2.0),
LICENSE.lgpl21, and LICENSE.bsd-2-clause.
