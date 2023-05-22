/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Viasat */
#include <argp.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "linkevents.h"
#include "linkevents.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define PERF_BUFFER_PAGES	1024
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)
#define info(...) { if (verbose) { fprintf(stderr, __VA_ARGS__); } }

static volatile sig_atomic_t exiting = 0;
static bool verbose = false;
static __u64 boottime_epoch_ms = 0;

const char *argp_program_version = "linkevents 1.0";
const char *argp_program_bug_address = "https://github.com/LonoCloud/ebpf-linkevents";
const char argp_program_doc[] =
"Print JSON link events from all network namespaces.\n"
"\n"
"USAGE: linkevents [-v]\n"
"\n"
"EXAMPLES:\n"
"    linkevents\n"
"    linkevents -v\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_size)
{
	struct event_t *e = data;
	char mac[6*3], ip[4*4];
	snprintf(mac, 6*3, "%02x:%02x:%02x:%02x:%02x:%02x",
		 (unsigned char)e->dev_addr[0],
		 (unsigned char)e->dev_addr[1],
		 (unsigned char)e->dev_addr[2],
		 (unsigned char)e->dev_addr[3],
		 (unsigned char)e->dev_addr[4],
		 (unsigned char)e->dev_addr[5]);
	inet_ntop(AF_INET, &e->ifa_address, ip, 16);

	printf("{\"ts\":%llu,"
	       "\"source\":\"%s\","
	       "\"type\":%d,\"name\":\"%s\",\"ifindex\":%d,"
	       "\"dev_addr\":\"%s\",\"ifa_address\":\"%s\","
	       "\"flags\":%u,\"nsid\":%u}\n",
	       e->ts / 1000000 + boottime_epoch_ms, // epoch ms
	       e->source == 0 ? "link" : "addr",
	       e->type, e->name, e->ifindex,
	       mac, ip,
	       e->flags, e->nsid);
	fflush(stdout);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static void sig_int(int signo)
{
	exiting = 1;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct linkevents_bpf *obj = NULL;
	struct perf_buffer *pb = NULL;
	struct timespec ts;
	__u64 realtime_ms, boottime_ms;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	info("Saving boot epoch time (milliseconds)\n");
	clock_gettime(CLOCK_REALTIME, &ts);
	realtime_ms = (ts.tv_sec * 1000000000ULL + ts.tv_nsec) / 1000000;
	clock_gettime(CLOCK_BOOTTIME, &ts);
	boottime_ms =  (ts.tv_sec * 1000000000ULL + ts.tv_nsec) / 1000000;
	boottime_epoch_ms = realtime_ms - boottime_ms;

	info("Checking BTF for CO-RE\n");
	err = ensure_core_btf(&open_opts);
	if (err) {
		warn("failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		goto cleanup;
	}

	obj = linkevents_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		goto cleanup;
	}

	/* It fallbacks to kprobes when kernel does not support fentry. */
	if (fentry_can_attach("rtmsg_ifinfo_build_skb", NULL)) {
		info("Using kprobe attachments\n");
		bpf_program__set_autoload(obj->progs.kprobe_rtmsg_ifinfo_build_skb, false);
		bpf_program__set_autoload(obj->progs.kprobe_rtmsg_ifa, false);
	} else {
		info("Using fentry attachments\n");
		bpf_program__set_autoload(obj->progs.fentry_rtmsg_ifinfo_build_skb, false);
		bpf_program__set_autoload(obj->progs.fentry_rtmsg_ifa, false);
	}

	info("Loading BPF object\n");
	err = linkevents_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	info("Attaching BPF programs\n");
	err = linkevents_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	info("Registering event handlers\n");
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	info("Loaded and Running\n");
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	linkevents_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
