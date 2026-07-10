from bcc import BPF
from ctypes import *
from collections import defaultdict
import time

import matplotlib.pyplot as plt
import networkx as nx


TASK_COMM_LEN = 16
MAX_ARGS = 20
ARG_LEN = 128
PATH_LEN = 256

EDGE_CREATE = 1
EDGE_ATTR = 2
EDGE_EXEC = 3

TRIGGER_SYSCALL = 1
TRIGGER_EXECVE_CRED_TRANSITION = 2


class ProcAttr(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("ppid", c_uint),
        ("euid", c_uint),
        ("egid", c_uint),
        ("ts", c_ulonglong),
    ]


class ExecEvent(Structure):
    _fields_ = [
        ("attr", ProcAttr),
        ("syscall", c_uint),
        ("comm", c_char * TASK_COMM_LEN),
        ("argv", (c_char * ARG_LEN) * MAX_ARGS),
        ("argc", c_int),
    ]


class ForkEvent(Structure):
    _fields_ = [
        ("parent", ProcAttr),
        ("child_pid", c_uint),
        ("type", c_uint),
    ]


class FileEvent(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("uid", c_uint),
        ("edge", c_uint),
        ("inode", c_ulonglong),
        ("dev", c_uint),
        ("ts", c_ulonglong),
        ("comm", c_char * TASK_COMM_LEN),
        ("path", c_char * PATH_LEN),
    ]


class PrivEvent(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("ppid", c_uint),
        ("uid", c_uint),
        ("euid", c_uint),
        ("gid", c_uint),
        ("egid", c_uint),
        ("old_uid", c_uint),
        ("old_euid", c_uint),
        ("old_gid", c_uint),
        ("old_egid", c_uint),
        ("trigger_type", c_uint),
        ("syscall_id", c_uint),
        ("cap_effective", c_ulonglong),
        ("old_cap_effective", c_ulonglong),
        ("comm", c_char * TASK_COMM_LEN),
    ]


class SudoEvent(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("uid", c_uint),
        ("path", c_char * 80),
    ]


bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/fcntl.h>

#define PATH_LEN 256
#define MAX_ARGS 20
#define ARG_LEN 128

#define MIN_PID 1000
#define RATE_LIMIT_NS 100000000

#define __NR_setuid        105
#define __NR_setgid        106
#define __NR_setreuid      113
#define __NR_setregid      114
#define __NR_setresuid     117
#define __NR_setresgid     119
#define __NR_capset        126

#define TRIGGER_SYSCALL 1
#define TRIGGER_EXECVE_CRED_TRANSITION 2

BPF_HASH(rate_limiter, u32, u64, 10240);

struct proc_attr_t {
    u32 pid;
    u32 ppid;
    u32 euid;
    u32 egid;
    u64 ts;
};

struct exec_event_t {
    struct proc_attr_t attr;
    u32 syscall;
    char comm[TASK_COMM_LEN];
    char argv[MAX_ARGS][ARG_LEN];
    int argc;
};

struct fork_event_t {
    struct proc_attr_t parent;
    u32 child_pid;
    u32 type;
};

enum file_edge_t {
    EDGE_CREATE = 1,
    EDGE_ATTR   = 2,
    EDGE_EXEC   = 3,
};

struct file_event_t {
    u32 pid;
    u32 uid;
    u32 edge;
    u64 inode;
    u32 dev;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char path[PATH_LEN];
};

struct open_info_t {
    char path[PATH_LEN];
    int flags;
};

struct sudo_event_t {
    u32 pid;
    u32 uid;
    char path[80];
};

struct cred_snapshot_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 euid;
    u32 gid;
    u32 egid;
    u64 cap_effective;
    u64 cap_permitted;
};

struct priv_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 euid;
    u32 gid;
    u32 egid;
    u32 old_uid;
    u32 old_euid;
    u32 old_gid;
    u32 old_egid;
    u32 trigger_type;
    u32 syscall_id;
    u64 cap_effective;
    u64 old_cap_effective;
    char comm[TASK_COMM_LEN];
};

BPF_PERCPU_ARRAY(exec_storage, struct exec_event_t, 1);
BPF_PERCPU_ARRAY(file_storage, struct file_event_t, 1);
BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(fork_events);
BPF_PERF_OUTPUT(file_events);
BPF_PERF_OUTPUT(priv_events);
BPF_PERF_OUTPUT(sudo_events);

BPF_HASH(open_map, u32, struct open_info_t);
BPF_HASH(exec_cred_snapshots, u32, struct cred_snapshot_t, 8192);

static __always_inline int read_task_creds(struct cred_snapshot_t *out)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred *cred = NULL;
    struct task_struct *parent = NULL;

    out->pid = bpf_get_current_pid_tgid() >> 32;

    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent)
        bpf_probe_read_kernel(&out->ppid, sizeof(out->ppid), &parent->tgid);

    bpf_probe_read_kernel(&cred, sizeof(cred), &task->cred);
    if (!cred)
        return -1;

    bpf_probe_read_kernel(&out->uid, sizeof(out->uid), &cred->uid.val);
    bpf_probe_read_kernel(&out->euid, sizeof(out->euid), &cred->euid.val);
    bpf_probe_read_kernel(&out->gid, sizeof(out->gid), &cred->gid.val);
    bpf_probe_read_kernel(&out->egid, sizeof(out->egid), &cred->egid.val);
    bpf_probe_read_kernel(&out->cap_effective, sizeof(out->cap_effective), &cred->cap_effective.val);
    bpf_probe_read_kernel(&out->cap_permitted, sizeof(out->cap_permitted), &cred->cap_permitted.val);
    return 0;
}

static __always_inline int fill_proc_attr(struct proc_attr_t *a)
{
    struct cred_snapshot_t c = {};

    if (read_task_creds(&c) < 0)
        return 1;

    a->pid = c.pid;
    if (a->pid < MIN_PID)
        return 1;

    u64 now = bpf_ktime_get_ns();
    u32 pid = a->pid;
    u64 *last_time = rate_limiter.lookup(&pid);

    if (last_time && (now - *last_time) < RATE_LIMIT_NS)
        return 1;

    rate_limiter.update(&pid, &now);
    a->ppid = c.ppid;
    a->euid = c.euid;
    a->egid = c.egid;
    a->ts = now;
    return 0;
}

static __always_inline void fill_priv_event(struct priv_event_t *e,
                                            struct cred_snapshot_t *c,
                                            u32 trigger_type,
                                            u32 syscall_id)
{
    e->pid = c->pid;
    e->ppid = c->ppid;
    e->uid = c->uid;
    e->euid = c->euid;
    e->gid = c->gid;
    e->egid = c->egid;
    e->trigger_type = trigger_type;
    e->syscall_id = syscall_id;
    e->cap_effective = c->cap_effective;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

int trace_execve(struct tracepoint__syscalls__sys_enter_execve *ctx)
{
    /* execve credential snapshot */
    struct cred_snapshot_t snap = {};
    if (read_task_creds(&snap) == 0 && snap.pid >= MIN_PID) {
        u32 snap_pid = snap.pid;
        exec_cred_snapshots.update(&snap_pid, &snap);
    }

    int zero = 0;
    struct exec_event_t *e = exec_storage.lookup(&zero);
    if (!e)
        return 0;

    e->argc = 0;

    if (fill_proc_attr(&e->attr))
        return 0;

    e->syscall = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]);
        if (!argp)
            break;
        bpf_probe_read_user_str(e->argv[i], ARG_LEN, argp);
        e->argc = i + 1;
    }

    exec_events.perf_submit(ctx, e, sizeof(*e));
    return 0;
}

int trace_execveat(struct tracepoint__syscalls__sys_enter_execveat *ctx)
{
    /* execve credential snapshot */
    struct cred_snapshot_t snap = {};
    if (read_task_creds(&snap) == 0 && snap.pid >= MIN_PID) {
        u32 snap_pid = snap.pid;
        exec_cred_snapshots.update(&snap_pid, &snap);
    }

    int zero = 0;
    struct exec_event_t *e = exec_storage.lookup(&zero);
    if (!e)
        return 0;

    e->argc = 0;

    if (fill_proc_attr(&e->attr))
        return 0;

    e->syscall = 2;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]);
        if (!argp)
            break;
        bpf_probe_read_user_str(e->argv[i], ARG_LEN, argp);
        e->argc = i + 1;
    }

    exec_events.perf_submit(ctx, e, sizeof(*e));
    return 0;
}

int trace_fork_exit(struct tracepoint__syscalls__sys_exit_fork *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    struct fork_event_t e = {};
    e.type = 1;
    if (fill_proc_attr(&e.parent))
        return 0;

    e.child_pid = ctx->ret;
    fork_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int trace_vfork_exit(struct tracepoint__syscalls__sys_exit_vfork *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    struct fork_event_t e = {};
    e.type = 2;
    if (fill_proc_attr(&e.parent))
        return 0;

    e.child_pid = ctx->ret;
    fork_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int trace_clone_exit(struct tracepoint__syscalls__sys_exit_clone *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    struct fork_event_t e = {};
    e.type = 3;
    if (fill_proc_attr(&e.parent))
        return 0;

    e.child_pid = ctx->ret;
    fork_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int trace_clone3_exit(struct tracepoint__syscalls__sys_exit_clone3 *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    struct fork_event_t e = {};
    e.type = 4;
    if (fill_proc_attr(&e.parent))
        return 0;

    e.child_pid = ctx->ret;
    fork_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < MIN_PID)
        return 0;

    struct open_info_t info = {};
    info.flags = args->flags;

    bpf_probe_read_user_str(info.path, sizeof(info.path), args->filename);
    open_map.update(&pid, &info);

    if ((info.flags & O_WRONLY) || (info.flags & O_RDWR)) {
        struct sudo_event_t e = {};
        e.pid = pid;
        e.uid = bpf_get_current_uid_gid();
        bpf_probe_read_kernel(&e.path, sizeof(e.path), &info.path);
        sudo_events.perf_submit(args, &e, sizeof(e));
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < MIN_PID)
        return 0;

    int ret = args->ret;
    if (ret < 0)
        goto cleanup;

    struct open_info_t *info = open_map.lookup(&pid);
    if (!info)
        return 0;

    if (!(info->flags & O_CREAT))
        goto cleanup;

    int zero = 0;
    struct file_event_t *e = file_storage.lookup(&zero);
    if (!e)
        goto cleanup;

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid();
    e->edge = EDGE_CREATE;
    e->ts = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(&e->path, info->path, sizeof(e->path));

    file_events.perf_submit(args, e, sizeof(*e));

cleanup:
    open_map.delete(&pid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat)
{
    struct file_event_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    if (e.pid < MIN_PID)
        return 0;

    e.uid = bpf_get_current_uid_gid();
    e.edge = EDGE_ATTR;
    e.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(e.path, sizeof(e.path), args->filename);

    file_events.perf_submit(args, &e, sizeof(e));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
    if (args->ret < 0) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        exec_cred_snapshots.delete(&pid);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execveat)
{
    if (args->ret < 0) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        exec_cred_snapshots.delete(&pid);
    }
    return 0;
}

/* execve-time credential transition detection */
TRACEPOINT_PROBE(sched, sched_process_exec)
{
    struct cred_snapshot_t cur_snap = {};
    if (read_task_creds(&cur_snap) < 0)
        return 0;

    u32 pid = cur_snap.pid;
    struct cred_snapshot_t *old = exec_cred_snapshots.lookup(&pid);
    if (!old)
        return 0;

    int gained_effective_cap =
        (old->cap_effective != cur_snap.cap_effective) && cur_snap.cap_effective != 0;

    if (((old->euid != cur_snap.euid) && cur_snap.euid == 0) ||
        ((old->egid != cur_snap.egid) && cur_snap.egid == 0) ||
        gained_effective_cap) {
        struct priv_event_t e = {};
        fill_priv_event(&e, &cur_snap, TRIGGER_EXECVE_CRED_TRANSITION, 0);
        e.old_uid = old->uid;
        e.old_euid = old->euid;
        e.old_gid = old->gid;
        e.old_egid = old->egid;
        e.old_cap_effective = old->cap_effective;
        priv_events.perf_submit(args, &e, sizeof(e));
    }

    exec_cred_snapshots.delete(&pid);
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    u32 id = args->id;

    if (id != __NR_setuid &&
        id != __NR_setgid &&
        id != __NR_setreuid &&
        id != __NR_setregid &&
        id != __NR_setresuid &&
        id != __NR_setresgid &&
        id != __NR_capset)
        return 0;

    if (args->ret != 0)
        return 0;

    struct cred_snapshot_t cur_snap = {};
    if (read_task_creds(&cur_snap) < 0)
        return 0;

    if (cur_snap.pid < MIN_PID)
        return 0;

    struct priv_event_t e = {};
    fill_priv_event(&e, &cur_snap, TRIGGER_SYSCALL, id);
    priv_events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""


syscall_names = {
    105: "setuid",
    106: "setgid",
    113: "setreuid",
    114: "setregid",
    117: "setresuid",
    119: "setresgid",
    126: "capset",
}


def provstorage(outputstr):
    with open("Provenance.log", "a") as f:
        f.write(outputstr + "\n")


def decode_comm(comm):
    return comm.decode(errors="replace").strip("\x00")


def handle_exec(cpu, data, size):
    e = cast(data, POINTER(ExecEvent)).contents
    if e.argc == 0:
        return

    syscall = "execve" if e.syscall == 1 else "execveat"
    cmdline = " ".join(e.argv[i].value.decode(errors="replace") for i in range(e.argc))
    outputstr = (
        "EXEC"
        + "|"
        + str(syscall)
        + "|"
        + str(e.attr.ts)
        + "|"
        + str(e.attr.pid)
        + "|"
        + str(e.attr.ppid)
        + "|"
        + str(e.attr.euid)
        + "|"
        + str(decode_comm(e.comm))
        + "|"
        + str(cmdline)
    )

    provstorage(outputstr)


def handle_fork(cpu, data, size):
    e = cast(data, POINTER(ForkEvent)).contents
    t = {1: "fork", 2: "vfork", 3: "clone", 4: "clone3"}[e.type]
    outputstr = str(t.upper()) + "|" + str(e.child_pid) + "|" + str(e.parent.pid) + "|" + str(e.parent.ts)

    provstorage(outputstr)


def handle_file(cpu, data, size):
    e = cast(data, POINTER(FileEvent)).contents
    edge = {
        EDGE_CREATE: "FILE_CREATE",
        EDGE_ATTR: "ATTR",
        EDGE_EXEC: "EXEC",
    }.get(e.edge, "?")
    outputstr = (
        str(edge)
        + "|"
        + str(e.uid)
        + "|"
        + str(e.pid)
        + "|"
        + str(e.inode)
        + "|"
        + str(e.dev)
        + "|"
        + str(e.path.decode(errors="ignore"))
        + "|"
        + str(e.comm.decode(errors="ignore"))
    )
    if ("python3" not in e.comm.decode(errors="ignore")) and ("/dev/shm" not in outputstr):
        provstorage(outputstr)


def parse_log(file_path):
    parent_map = {}
    children_map = defaultdict(set)
    all_edges = []
    labels = {}

    with open(file_path, "r") as f:
        lines = f.readlines()
    for line in lines:
        parts = line.strip().split("|")
        if not parts:
            continue

        event = parts[0]

        if event in ("CLONE", "CLONE3", "FORK", "VFORK"):
            child = parts[1]
            parent = parts[2]

            parent_map[child] = parent
            children_map[parent].add(child)

            all_edges.append((parent, child, "fork"))

        elif event == "EXEC":
            pid = parts[3]
            ppid = parts[4]
            comm = parts[6]
            cmd = parts[7]

            parent_map[pid] = ppid
            children_map[ppid].add(pid)

            labels[pid] = f"{comm}\n{cmd}"

            all_edges.append((ppid, pid, "exec"))

    return parent_map, children_map, all_edges, labels


def trace_lineage(pid, parent_map):
    lineage = []
    current = pid

    while current in parent_map:
        lineage.append(current)
        parent = parent_map[current]

        if parent == current:
            break

        current = parent

    return lineage


drawn = []


def draw_graph(G, labels, pid):
    pos = nx.nx_agraph.graphviz_layout(G, prog="dot")
    plt.figure(figsize=(14, 12))
    output = "Picture/PID" + str(pid) + "_" + str(time.time()) + ".png"
    node_colors = []
    for node in G.nodes():
        if str(node) == str(pid):
            node_colors.append("red")
        else:
            node_colors.append("#A7C7E7")

    nx.draw(
        G,
        pos,
        with_labels=False,
        node_size=2500,
        node_color=node_colors,
        arrows=True,
    )

    draw_labels = {}
    for node in G.nodes():
        if node in labels:
            draw_labels[node] = f"{node}\n{labels[node]}"
        else:
            draw_labels[node] = node

    nx.draw_networkx_labels(G, pos, draw_labels, font_size=8)

    plt.title("Provenance Graph (Top-Down Hierarchical)")
    plt.savefig(output, dpi=300)
    print(f"Saved to {output}")
    plt.show()


def build_expanded_graph(target_pid1):
    target_pid = str(target_pid1)
    if target_pid not in drawn:
        drawn.append(target_pid)
    else:
        return
    G = nx.DiGraph()
    parent_map, children_map, all_edges, labels = parse_log("Provenance.log")
    if target_pid not in parent_map:
        print("target pid not in parent map")
    lineage = trace_lineage(target_pid, parent_map)
    pid = str(target_pid)
    try:
        sudo_authen_log = "".join(open("SudoAuthen.log", "r").readlines())
    except FileNotFoundError:
        sudo_authen_log = ""

    for node in lineage:
        if node in parent_map:
            parent = parent_map[node]
            G.add_edge(parent, node, type="lineage")

    for node in lineage:
        if node in sudo_authen_log:
            return
        if node in parent_map:
            parent = parent_map[node]
            G.add_edge(parent, node, type="neighbor")

        if node in children_map:
            for child in children_map[node]:
                if child in sudo_authen_log:
                    return
                G.add_edge(node, child, type="neighbor")

    draw_graph(G, labels, pid)


def handle_priv_event(cpu, data, size):
    e = cast(data, POINTER(PrivEvent)).contents
    comm = decode_comm(e.comm)

    if e.trigger_type == TRIGGER_EXECVE_CRED_TRANSITION:
        trigger = "execve_cred_transition"
    else:
        trigger = "syscall_credential_trigger"

    syscall = syscall_names.get(e.syscall_id, "none")
    print(
        "[PRIV-TRIGGER] "
        f"type={trigger} syscall={syscall} pid={e.pid} ppid={e.ppid} comm={comm} "
        f"uid={e.old_uid}->{e.uid} euid={e.old_euid}->{e.euid} "
        f"gid={e.old_gid}->{e.gid} egid={e.old_egid}->{e.egid} "
        f"cap_effective=0x{e.old_cap_effective:016x}->0x{e.cap_effective:016x}"
    )
    build_expanded_graph(e.pid)


def print_sudo_authen(cpu, data, size):
    e = cast(data, POINTER(SudoEvent)).contents
    path = e.path.decode("utf-8", "ignore")

    if ".sudo_as_admin_successful" not in path:
        return

    print(f"[SUDO AUTH] PID={e.pid} UID={e.uid} FILE={path}")

    with open("SudoAuthen.log", "a") as f:
        f.write("\n" + str(e.uid) + "|" + str(e.pid) + "|")


def main():
    b = BPF(text=bpf_program)

    b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_execve")
    b.attach_tracepoint(tp="syscalls:sys_enter_execveat", fn_name="trace_execveat")
    b.attach_tracepoint(tp="syscalls:sys_exit_fork", fn_name="trace_fork_exit")
    b.attach_tracepoint(tp="syscalls:sys_exit_vfork", fn_name="trace_vfork_exit")
    b.attach_tracepoint(tp="syscalls:sys_exit_clone", fn_name="trace_clone_exit")
    b.attach_tracepoint(tp="syscalls:sys_exit_clone3", fn_name="trace_clone3_exit")

    b["exec_events"].open_perf_buffer(handle_exec)
    b["fork_events"].open_perf_buffer(handle_fork)
    b["file_events"].open_perf_buffer(handle_file, page_cnt=64)
    b["priv_events"].open_perf_buffer(handle_priv_event)
    b["sudo_events"].open_perf_buffer(print_sudo_authen)

    print("Tracing provenance and privilege triggers ... Ctrl-C to stop.")
    print("Run with: sudo python3 detector.py")

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
