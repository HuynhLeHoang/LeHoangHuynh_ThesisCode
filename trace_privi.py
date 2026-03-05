from bcc import BPF
from ctypes import *
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict
import time

bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/fcntl.h>

#define __NR_setuid        105
#define __NR_setgid        106
#define __NR_setreuid     113
#define __NR_setregid     114
#define __NR_setresuid   117
#define __NR_setresgid   119
#define __NR_capset      126



struct event_t {
    u32 pid;
    u32 uid;
    u32 syscall;
};
BPF_PERF_OUTPUT(events);
struct sudo_event_t {
    u32 pid;
    u32 uid;
    char path[80];
};
BPF_PERF_OUTPUT(sudo_events);
TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    int flags = args->flags;

    if (!(flags & O_WRONLY) && !(flags & O_RDWR))
        return 0;

    struct sudo_event_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid();

    bpf_probe_read_user_str(e.path, sizeof(e.path), args->filename);

    sudo_events.perf_submit(args, &e, sizeof(e));

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

    /* chỉ log khi thành công */
    if (args->ret != 0)
        return 0;

    struct event_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid();
    e.syscall = id;

    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""

class Event(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("uid", c_uint),
        ("syscall", c_uint),
    ]

class SudoEvent(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("uid", c_uint),
        ("path", c_char * 80),
    ]

syscall_names = {
    105: "setuid",
    106: "setgid",
    113: "setreuid",
    114: "setregid",
    117: "setresuid",
    119: "setresgid",
    126: "capset",
}


def parse_log(file_path):
    parent_map = {}
    children_map = defaultdict(set)
    all_edges = []
    labels = {}

    with open(file_path, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if not parts:
                continue

            event = parts[0]

            # ===== CLONE / CLONE3 =====
            if event in ("CLONE", "CLONE3"):
                child = parts[1]
                parent = parts[2]

                parent_map[child] = parent
                children_map[parent].add(child)

                all_edges.append((parent, child, "fork"))

            # ===== EXEC =====
            elif event == "EXEC":
                # EXEC|execve|timestamp|pid|ppid|uid|comm|cmd
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


def build_expanded_graph(target_pid, parent_map, children_map, all_edges):
    G = nx.DiGraph()

    lineage = trace_lineage(target_pid, parent_map)
    lineage_set = set(lineage)

    for node in lineage:
        if node in parent_map:
            parent = parent_map[node]
            G.add_edge(parent, node, type="lineage")

    for node in lineage:

        if node in parent_map:
            parent = parent_map[node]
            G.add_edge(parent, node, type="neighbor")

        if node in children_map:
            for child in children_map[node]:
                G.add_edge(node, child, type="neighbor")

    return G


def draw_graph(G, labels,pid):
    pos = nx.nx_agraph.graphviz_layout(G, prog="dot")
    plt.figure(figsize=(14, 12))
    output= str(pid) + '_' + str(time.time()) + ".png"
    nx.draw(
        G,
        pos,
        with_labels=False,
        node_size=2500,
        node_color="#A7C7E7",
        arrows=True
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

def print_event(cpu, data, size):
    e = cast(data, POINTER(Event)).contents
    name = syscall_names.get(e.syscall, "unknown")
    parent_map, children_map, all_edges, labels = parse_log("Provenance.log")
    target_pid = e.pid
    SudoAuthenLog = ''.join(open("SudoAuthen.log","r").readlines())
    pid = e.pid
    print("value of if:",str(target_pid) not in parent_map)
    checker = False
    while True:        
        for children in children_map[pid]:
            if str(children) in SudoAuthenLog:
                break
                #return
        try:
            pid = parent_map[pid]
        except:
            checker = True
            break
    print(f"[PID {e.pid}] UID={e.uid} SUCCESS syscall={name}")
    #print(parent_map)
    if target_pid not in parent_map:
        print("PID not exist")
    else:
        G = build_expanded_graph(target_pid, parent_map, children_map, all_edges)
        draw_graph(G, labels, target_pid)

def print_sudo_authen(cpu, data, size):
    e = cast(data, POINTER(SudoEvent)).contents
    path = e.path.decode("utf-8", "ignore")

    if ".sudo_as_admin_successful" not in path:
        return

    print(f"[SUDO AUTH] PID={e.pid} UID={e.uid} FILE={path}")

    with open("SudoAuthen.log","w") as f:
        f.write(str(e.uid) + "|" + str(e.pid))

b = BPF(text=bpf_program)
b["sudo_events"].open_perf_buffer(print_sudo_authen)
b["events"].open_perf_buffer(print_event)

print("Tracing successful privilege-changing syscalls... Ctrl-C to stop.")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
