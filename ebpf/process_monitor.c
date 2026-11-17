// eBPF process and network monitor (educational, read-only).
//
// One program on the raw sys_enter tracepoint. It runs at the entry of every system call,
// returns at once unless the call is execve, execveat, connect, ptrace, memfd_create or
// mmap, and for those fills one event_t and sends it to user space through a perf event
// array.
//
// The program only reads. It never changes a syscall's arguments or its result.
//
// Why the raw tracepoint and not the six syscalls:sys_enter_* tracepoints: an earlier version
// attached one program to each of those, and on the CI runner (kernel 7.0, four CPUs) events
// from sys_enter_execve, sys_enter_execveat and sys_enter_memfd_create arrived only for calls
// made on CPU 0, so most of those calls went unseen, while connect and ptrace events arrived
// from every CPU. The cause was not tracked down. The raw tracepoint does not go through a
// per-CPU perf event to reach the program, and with it events arrive from every CPU.
//
// What is decided here and what is left to user space: every execve, execveat, connect,
// ptrace and memfd_create call is reported, and the agent's rules decide what matters. The
// one filter is on mmap (see below), because reporting every executable mapping would mean
// one event per shared-library load on the whole host, and a perf buffer that full loses
// the events that do matter.

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

// The raw tracepoint hands over the kernel's saved user registers (struct pt_regs) and the
// syscall number. Where the arguments sit in those registers, what the numbers are, and how
// to tell a native call from a 32-bit compatibility one all depend on the architecture.
// They are written out here so the file builds without vmlinux.h or kernel headers.
// The Makefile passes -D__TARGET_ARCH_x86 or -D__TARGET_ARCH_arm64.
#if defined(__TARGET_ARCH_x86)

// x86-64 struct pt_regs: r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi
// orig_rax rip cs eflags rsp ss, eight bytes each. Syscall arguments: rdi rsi rdx r10 r8 r9.
#define REG_ARG0 112
#define REG_ARG1 104
#define REG_ARG2 96
#define REG_ARG3 56
#define REG_ARG4 72
#define REG_MODE 136                     // cs
#define IS_NATIVE(mode) ((mode) == 0x33) // 64-bit user code segment

#define NR_MMAP 9
#define NR_CONNECT 42
#define NR_EXECVE 59
#define NR_PTRACE 101
#define NR_MEMFD_CREATE 319
#define NR_EXECVEAT 322

#elif defined(__TARGET_ARCH_arm64)

// arm64 struct pt_regs starts with x0..x30, sp, pc, pstate. Syscall arguments: x0..x5.
#define REG_ARG0 0
#define REG_ARG1 8
#define REG_ARG2 16
#define REG_ARG3 24
#define REG_ARG4 32
#define REG_MODE 264                           // pstate
#define IS_NATIVE(mode) (((mode) & 0x10) == 0) // PSR_MODE32_BIT clear

#define NR_CONNECT 203
#define NR_PTRACE 117
#define NR_EXECVE 221
#define NR_MMAP 222
#define NR_MEMFD_CREATE 279
#define NR_EXECVEAT 281

#else
#error "build with -D__TARGET_ARCH_x86 or -D__TARGET_ARCH_arm64 (the Makefile does this)"
#endif

#define TASK_COMM_LEN 16
#define FILE_NAME_LEN 256
#define EVENT_TYPE_LEN 16

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
    __u32 family;      // connect: address family as passed (0 if it could not be read)
    __s32 dirfd;       // execveat: directory file descriptor argument
    __u64 arg0;        // ptrace: request. mmap: prot. execveat: flags
    __u64 arg1;        // mmap: flags
    __u8 dst_ip6[16];  // connect, AF_INET6: address
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

// `name` must be a string literal shorter than EVENT_TYPE_LEN.
#define SET_TYPE(evt, name)                                                         \
    ({                                                                              \
        _Static_assert(sizeof(name) <= EVENT_TYPE_LEN, "event type name too long"); \
        __builtin_memcpy((evt).event_type, name, sizeof(name));                     \
    })

static __always_inline unsigned long read_reg(const void *regs, int offset) {
    unsigned long value = 0;
    bpf_probe_read_kernel(&value, sizeof(value), regs + offset);
    return value;
}

// Decodes the sockaddr a connect() was given. IPv4 and IPv6 destinations are filled in; for
// any other family (a Unix socket, netlink) only the family is carried.
static __always_inline void fill_connect(struct event_t *evt, const void *uaddr, int addrlen) {
    __u16 family = 0;

    if (!uaddr || addrlen < (int)sizeof(family) ||
        bpf_probe_read_user(&family, sizeof(family), uaddr) != 0)
        return;
    evt->family = family;

    if (family == AF_INET && addrlen >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in sa = {};
        if (bpf_probe_read_user(&sa, sizeof(sa), uaddr) == 0) {
            evt->dst_ip = sa.sin_addr.s_addr;
            evt->dst_port = sa.sin_port;
        }
    } else if (family == AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 sa6 = {};
        if (bpf_probe_read_user(&sa6, sizeof(sa6), uaddr) == 0) {
            evt->dst_port = sa6.sin6_port;
            __builtin_memcpy(evt->dst_ip6, &sa6.sin6_addr, sizeof(evt->dst_ip6));
        }
    }
}

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    long id = (long)ctx->args[1];

    if (id != NR_EXECVE && id != NR_EXECVEAT && id != NR_CONNECT && id != NR_PTRACE &&
        id != NR_MEMFD_CREATE && id != NR_MMAP)
        return 0;

    const void *regs = (const void *)ctx->args[0];

    // A 32-bit compatibility call uses a different numbering, so its number means something
    // else. Such calls are not traced.
    if (!IS_NATIVE(read_reg(regs, REG_MODE)))
        return 0;

    unsigned long arg0 = read_reg(regs, REG_ARG0);
    unsigned long arg1 = read_reg(regs, REG_ARG1);
    unsigned long arg2 = read_reg(regs, REG_ARG2);
    unsigned long arg3 = read_reg(regs, REG_ARG3);

    // mmap(addr, length, prot, flags, fd, offset).
    //
    // Reported: an executable mapping that is also writable, or that is anonymous (not backed
    // by a file). Not reported: an executable, read-only mapping of a file, which is what
    // loading any program or shared library does. That one case is filtered here and not in
    // user space because of its volume; see the note at the top of the file.
    if (id == NR_MMAP) {
        if (!(arg2 & PROT_EXEC))
            return 0;
        if (!(arg2 & PROT_WRITE) && !(arg3 & MAP_ANONYMOUS))
            return 0;
    }

    struct event_t evt = {};
    __u64 uid_gid = bpf_get_current_uid_gid();

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = uid_gid & 0xffffffff;
    evt.gid = uid_gid >> 32;
    evt.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    if (id == NR_EXECVE) {
        // execve(pathname, argv, envp)
        if (arg0)
            bpf_probe_read_user_str(evt.filename, FILE_NAME_LEN, (const char *)arg0);
        SET_TYPE(evt, "exec");
    } else if (id == NR_EXECVEAT) {
        // execveat(dirfd, pathname, argv, envp, flags). With an empty pathname and
        // AT_EMPTY_PATH it runs the file dirfd refers to, which is how fexecve() starts a
        // memfd-backed binary.
        evt.dirfd = (__s32)arg0;
        if (arg1)
            bpf_probe_read_user_str(evt.filename, FILE_NAME_LEN, (const char *)arg1);
        evt.arg0 = read_reg(regs, REG_ARG4);
        SET_TYPE(evt, "execveat");
    } else if (id == NR_CONNECT) {
        // connect(sockfd, addr, addrlen). Every call is reported, whatever the family.
        fill_connect(&evt, (const void *)arg1, (int)arg2);
        SET_TYPE(evt, "connect");
    } else if (id == NR_PTRACE) {
        // ptrace(request, pid, addr, data). Every call is reported with its request number;
        // which requests matter is the agent's decision.
        evt.arg0 = arg0;
        SET_TYPE(evt, "ptrace");
    } else if (id == NR_MEMFD_CREATE) {
        // memfd_create(name, flags)
        if (arg0)
            bpf_probe_read_user_str(evt.filename, FILE_NAME_LEN, (const char *)arg0);
        SET_TYPE(evt, "memfd");
    } else {
        evt.arg0 = arg2;
        evt.arg1 = arg3;
        SET_TYPE(evt, "mmap_exec");
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
