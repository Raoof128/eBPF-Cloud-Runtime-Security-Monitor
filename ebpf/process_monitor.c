// eBPF process and network monitor (educational, read-only).
//
// Six tracepoint programs on syscall entry: execve, execveat, connect, ptrace, memfd_create
// and mmap. Each fills one event_t and sends it to user space through a perf event array.
//
// The programs only read. They never change a syscall's arguments or its result.
//
// What is decided here and what is left to user space: the probe reports every execve,
// execveat, connect, ptrace and memfd_create call it sees, and the agent's rules decide what
// matters. The one filter is on mmap (see handle_mmap), because reporting every executable
// mapping would mean one event per shared-library load on the whole host, and a perf buffer
// that full loses the events that do matter.

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/mman.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#define TASK_COMM_LEN 16
#define FILE_NAME_LEN 256
#define EVENT_TYPE_LEN 16

// Layout of the context a syscalls:sys_enter_* tracepoint hands to a program. Declared here
// so the file builds without vmlinux.h.
struct sys_enter_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
};

// One event. agent/event.go decodes this byte for byte: keep the two in step. Every field
// sits on its natural alignment, so there is no hidden padding (the one pad byte is named).
struct event_t {
    __u32 pid;
    __u32 ppid;  // always 0: finding the parent needs task_struct offsets (CO-RE), not used here
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    __u32 dst_ip;    // connect, AF_INET: address in network byte order
    __u16 dst_port;  // connect, AF_INET and AF_INET6: port in network byte order
    __u8 proto;      // always 0: connect() does not say, and the socket is not looked up
    __u8 pad;
    __u32 family;       // connect: address family as passed (0 if it could not be read)
    __s32 dirfd;        // execveat: directory file descriptor argument
    __u64 arg0;         // ptrace: request. mmap: prot. execveat: flags
    __u64 arg1;         // mmap: flags
    __u8 dst_ip6[16];   // connect, AF_INET6: address
    char comm[TASK_COMM_LEN];
    char filename[FILE_NAME_LEN];
    char event_type[EVENT_TYPE_LEN];
};

_Static_assert(sizeof(struct event_t) == 360, "event_t layout changed: update agent/event.go");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline void fill_task_context(struct event_t *evt) {
    __u64 uid_gid = bpf_get_current_uid_gid();

    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = uid_gid & 0xffffffff;
    evt->gid = uid_gid >> 32;
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
}

// `name` must be a string literal shorter than EVENT_TYPE_LEN.
#define SUBMIT(ctx, evt, name)                                                        \
    ({                                                                                \
        _Static_assert(sizeof(name) <= EVENT_TYPE_LEN, "event type name too long");   \
        __builtin_memcpy((evt).event_type, name, sizeof(name));                       \
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &(evt), sizeof(evt)); \
    })

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct sys_enter_ctx *ctx) {
    struct event_t evt = {};
    fill_task_context(&evt);

    const char *filename = (const char *)ctx->args[0];
    if (filename)
        bpf_probe_read_user_str(evt.filename, FILE_NAME_LEN, filename);

    SUBMIT(ctx, evt, "exec");
    return 0;
}

// execveat(dirfd, pathname, argv, envp, flags). With an empty pathname and AT_EMPTY_PATH it
// runs the file that dirfd refers to, which is how fexecve() starts a memfd-backed binary.
SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat(struct sys_enter_ctx *ctx) {
    struct event_t evt = {};
    fill_task_context(&evt);

    evt.dirfd = (__s32)ctx->args[0];
    const char *filename = (const char *)ctx->args[1];
    if (filename)
        bpf_probe_read_user_str(evt.filename, FILE_NAME_LEN, filename);
    evt.arg0 = ctx->args[4];

    SUBMIT(ctx, evt, "execveat");
    return 0;
}

// Every connect() is reported, whatever the address family. The destination is decoded for
// IPv4 and IPv6; for anything else (a Unix socket, netlink) only the family is carried.
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct sys_enter_ctx *ctx) {
    struct event_t evt = {};
    fill_task_context(&evt);

    const void *uaddr = (const void *)ctx->args[1];
    int addrlen = (int)ctx->args[2];
    __u16 family = 0;

    if (uaddr && addrlen >= (int)sizeof(family) &&
        bpf_probe_read_user(&family, sizeof(family), uaddr) == 0) {
        evt.family = family;

        if (family == AF_INET && addrlen >= (int)sizeof(struct sockaddr_in)) {
            struct sockaddr_in sa = {};
            if (bpf_probe_read_user(&sa, sizeof(sa), uaddr) == 0) {
                evt.dst_ip = sa.sin_addr.s_addr;
                evt.dst_port = sa.sin_port;
            }
        } else if (family == AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 sa6 = {};
            if (bpf_probe_read_user(&sa6, sizeof(sa6), uaddr) == 0) {
                evt.dst_port = sa6.sin6_port;
                __builtin_memcpy(evt.dst_ip6, &sa6.sin6_addr, sizeof(evt.dst_ip6));
            }
        }
    }

    SUBMIT(ctx, evt, "connect");
    return 0;
}

// Every ptrace() is reported with its request number. Which requests matter is the agent's
// decision, not the probe's.
SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct sys_enter_ctx *ctx) {
    struct event_t evt = {};
    fill_task_context(&evt);
    evt.arg0 = ctx->args[0];

    SUBMIT(ctx, evt, "ptrace");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_memfd(struct sys_enter_ctx *ctx) {
    struct event_t evt = {};
    fill_task_context(&evt);

    const char *name = (const char *)ctx->args[0];
    if (name)
        bpf_probe_read_user_str(evt.filename, FILE_NAME_LEN, name);

    SUBMIT(ctx, evt, "memfd");
    return 0;
}

// mmap(addr, length, prot, flags, fd, offset).
//
// Reported: an executable mapping that is also writable, or that is anonymous (not backed by
// a file). Not reported: an executable, read-only mapping of a file, which is what loading
// any program or shared library does. That one case is filtered here and not in user space
// because of its volume; see the note at the top of the file.
SEC("tracepoint/syscalls/sys_enter_mmap")
int handle_mmap(struct sys_enter_ctx *ctx) {
    unsigned long prot = ctx->args[2];
    unsigned long flags = ctx->args[3];

    if (!(prot & PROT_EXEC))
        return 0;
    if (!(prot & PROT_WRITE) && !(flags & MAP_ANONYMOUS))
        return 0;

    struct event_t evt = {};
    fill_task_context(&evt);
    evt.arg0 = prot;
    evt.arg1 = flags;

    SUBMIT(ctx, evt, "mmap_exec");
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
