// eBPF process and network monitor (educational, read-only).
//
// Five tracepoint programs on syscall entry: execve, connect, ptrace, memfd_create and mmap.
// Each fills one event_t and sends it to user space through a perf event array.
//
// The programs only read. They never change a syscall's arguments or its result.

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/mman.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#define TASK_COMM_LEN 16
#define FILE_NAME_LEN 256
#define EVENT_TYPE_LEN 16

// ptrace requests that take control of, or write into, another process.
#define PTRACE_POKETEXT_REQ 4
#define PTRACE_POKEDATA_REQ 5
#define PTRACE_ATTACH_REQ 16
#define PTRACE_SEIZE_REQ 0x4206

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
    __u32 dst_ip;    // IPv4 address, network byte order (connect only)
    __u16 dst_port;  // network byte order (connect only)
    __u8 proto;
    __u8 pad;
    char comm[TASK_COMM_LEN];
    char filename[FILE_NAME_LEN];
    char event_type[EVENT_TYPE_LEN];
};

_Static_assert(sizeof(struct event_t) == 320, "event_t layout changed: update agent/event.go");

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

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct sys_enter_ctx *ctx) {
    const struct sockaddr *uservaddr = (const struct sockaddr *)ctx->args[1];
    int addrlen = (int)ctx->args[2];

    // Only IPv4 is decoded. Unix sockets, IPv6 and anything else are not reported.
    if (!uservaddr || addrlen < (int)sizeof(struct sockaddr_in))
        return 0;

    struct sockaddr_in sa = {};
    if (bpf_probe_read_user(&sa, sizeof(sa), uservaddr) != 0)
        return 0;
    if (sa.sin_family != AF_INET)
        return 0;

    struct event_t evt = {};
    fill_task_context(&evt);
    evt.dst_ip = sa.sin_addr.s_addr;
    evt.dst_port = sa.sin_port;
    // connect() does not say which protocol the socket uses, and the probe does not look the
    // socket up, so this is left at 0 (unknown). A UDP connect() is reported like a TCP one.
    evt.proto = 0;

    SUBMIT(ctx, evt, "connect");
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct sys_enter_ctx *ctx) {
    long request = (long)ctx->args[0];

    // Most ptrace calls are a debugger talking to a process it already controls. Report only
    // the requests that take control of a process or write into its memory.
    if (request != PTRACE_ATTACH_REQ && request != PTRACE_SEIZE_REQ &&
        request != PTRACE_POKETEXT_REQ && request != PTRACE_POKEDATA_REQ)
        return 0;

    struct event_t evt = {};
    fill_task_context(&evt);
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

SEC("tracepoint/syscalls/sys_enter_mmap")
int handle_mmap(struct sys_enter_ctx *ctx) {
    unsigned long prot = ctx->args[2];

    // Every shared library is mapped executable, so PROT_EXEC alone says nothing. A mapping
    // that is writable and executable at once is rarer (JIT compilers do it, and so does
    // injected code).
    if ((prot & (PROT_WRITE | PROT_EXEC)) != (PROT_WRITE | PROT_EXEC))
        return 0;

    struct event_t evt = {};
    fill_task_context(&evt);
    SUBMIT(ctx, evt, "mmap_wx");
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
