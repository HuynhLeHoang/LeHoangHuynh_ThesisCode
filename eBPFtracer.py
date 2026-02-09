from bcc import BPF
from ctypes import *
import sys
from queue import Queue
from threading import Thread
import time
event_queue = Queue(maxsize=1000000)
running = True
from bcc import BPF
from ctypes import *
import sys
from queue import Queue
from threading import Thread
import time
event_queue = Queue(maxsize=1000000)
running = True

TASK_COMM_LEN = 16
MAX_ARGS = 20
ARG_LEN = 128
PATH_LEN = 256

EDGE_CREATE   = 1
EDGE_ATTR   = 2
EDGE_EXEC  = 3

# =======================
# Python-side structures
# =======================

#basic attributes
class ProcAttr(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("ppid", c_uint),
        ("euid", c_uint),
        ("egid", c_uint),
        ("ts", c_ulonglong),
    ]

#extension attributes for Execve like Event
class ExecEvent(Structure):
    _fields_ = [
        ("attr", ProcAttr),
        ("syscall", c_uint),
        ("comm", c_char * TASK_COMM_LEN),
        ("argv", (c_char * ARG_LEN) * MAX_ARGS),
        ("argc", c_int),
    ]

#extension attributes for Fork like Event
class ForkEvent(Structure):
    _fields_ = [
        ("parent", ProcAttr),
        ("child_pid", c_uint),
        ("type", c_uint),
    ]

#attributes for File-Node event
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
# =======================
# eBPF program
# =======================

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/fs.h>

#define PATH_LEN 256
#define MAX_ARGS 20
#define ARG_LEN 128

//system process ID 
#define MIN_PID 1000
//bit rate 
#define RATE_LIMIT_NS 100000000
BPF_HASH(rate_limiter, u32, u64, 10240);

//basic attribute for a process node
struct proc_attr_t {
    u32 pid;
    u32 ppid;
    u32 euid;
    u32 egid;
    u64 ts;
};
struct exec_event_t {
    struct proc_attr_t attr;

    u32 syscall;    // 1=execve, 2=execveat
    char comm[TASK_COMM_LEN];
    char argv[MAX_ARGS][ARG_LEN];
    int argc;
};
struct fork_event_t {
    struct proc_attr_t parent;
    u32 child_pid;
    u32 type;   // fork/vfork/clone/clone3
};

//basic attribute for a file node
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

BPF_PERCPU_ARRAY(exec_storage, struct exec_event_t, 1);
BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(fork_events);
BPF_PERF_OUTPUT(file_events);

/* =========== Function definition area for process node ==============*/



//helper for credential
static __always_inline int fill_proc_attr(struct proc_attr_t *a)
{
    struct task_struct *task;

    a->pid = bpf_get_current_pid_tgid() >> 32;
    //system process filter apply
    if (a->pid < MIN_PID){
        return 1;
    }
    //rate limit apply
    u64 now = bpf_ktime_get_ns();
    u32 pid = a->pid;
    u64 *last_time = rate_limiter.lookup(&pid);
    
    if (last_time && (now - *last_time) < RATE_LIMIT_NS) {
        return 1;
    }
    rate_limiter.update(&pid, &now);

    task = (struct task_struct *)bpf_get_current_task();
    a->ppid = task->real_parent->tgid;

    u64 uidgid = bpf_get_current_uid_gid();
    a->euid = uidgid & 0xffffffff;
    a->egid = uidgid >> 32;

    a->ts = bpf_ktime_get_ns();
    return 0;
}

/* =======================
 * execve
 * ======================= */
int trace_execve(struct tracepoint__syscalls__sys_enter_execve *ctx)
{
    int zero = 0;
    struct exec_event_t *e = exec_storage.lookup(&zero);
    if (!e)
        return 0;

    e->argc = 0;

    if(fill_proc_attr(&e->attr)){
        return 0;
    }

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

/* =======================
 * execveat
 * ======================= */
int trace_execveat(struct tracepoint__syscalls__sys_enter_execveat *ctx)
{
    int zero = 0;
    struct exec_event_t *e = exec_storage.lookup(&zero);
    if (!e)
        return 0;

    e->argc = 0;

    if(fill_proc_attr(&e->attr)){
        return 0;
    }

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

/* =======================
 * fork / vfork / clone / clone3
 * ======================= */

int trace_fork_exit(struct tracepoint__syscalls__sys_exit_fork *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    struct fork_event_t e = {};
    e.type = 1;
    if(fill_proc_attr(&e.parent)){
        return 0;
    }
    
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
    if(fill_proc_attr(&e.parent)){
        return 0;
    }
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
    if(fill_proc_attr(&e.parent)){
        return 0;
    }
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
    if(fill_proc_attr(&e.parent)){
        return 0;
    }
    e.child_pid = ctx->ret;

    fork_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
/* =========== Function definition area for file node ==============*/

static __always_inline int submit_file(
    void *ctx,
    struct file *file,
    const char *path,
    u32 edge)
{
    struct inode *inode = NULL;
    umode_t mode = 0;

    if (!file)
        return 1;

    bpf_probe_read(&inode, sizeof(inode), &file->f_inode);
    if (!inode)
        return 1;

    bpf_probe_read(&mode, sizeof(mode), &inode->i_mode);
    if (!S_ISREG(mode))
        return 1;

    struct file_event_t e = {};
    //system process filter apply
    e.pid   = bpf_get_current_pid_tgid() >> 32;
    if (e.pid < MIN_PID){
        return 1;
    }
    //rate limit apply
    u64 now = bpf_ktime_get_ns();
    u32 pid = e.pid;
    u64 *last_time = rate_limiter.lookup(&pid);
    
    if (last_time && (now - *last_time) < RATE_LIMIT_NS) {
        return 0;
    }
    rate_limiter.update(&pid, &now);

    e.uid   = bpf_get_current_uid_gid();
    e.edge  = edge;
    u64 ino = 0;
    dev_t dev = 0;
    struct super_block *sb = NULL;

    bpf_probe_read(&ino, sizeof(ino), &inode->i_ino);
    bpf_probe_read(&sb, sizeof(sb), &inode->i_sb);
    if (sb)
        bpf_probe_read(&dev, sizeof(dev), &sb->s_dev);

    e.inode = ino;
    e.dev   = dev;
    e.ts    = bpf_ktime_get_ns();

    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    if (path)
        bpf_probe_read_user_str(e.path, sizeof(e.path), path);

    file_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

static __always_inline int submit_inode(
    void *ctx,
    struct inode *inode,
    u32 edge)
{
    umode_t mode = 0;
    struct file_event_t e = {};

    if (!inode)
        return 1;

    bpf_probe_read(&mode, sizeof(mode), &inode->i_mode);
    if (!S_ISREG(mode))
        return 1;

    e.pid = bpf_get_current_pid_tgid() >> 32;
    if (e.pid < MIN_PID)
        return 1;

    u64 now = bpf_ktime_get_ns();
    u32 pid = e.pid;
    u64 *last_time = rate_limiter.lookup(&pid);
    if (last_time && (now - *last_time) < RATE_LIMIT_NS)
        return 0;

    rate_limiter.update(&pid, &now);

    e.uid = bpf_get_current_uid_gid();
    e.edge = edge;

    bpf_probe_read(&e.inode, sizeof(e.inode), &inode->i_ino);

    struct super_block *sb = NULL;
    bpf_probe_read(&sb, sizeof(sb), &inode->i_sb);
    if (sb)
        bpf_probe_read(&e.dev, sizeof(e.dev), &sb->s_dev);

    e.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    // path không luôn available → để trống là OK cho provenance
    e.path[0] = '\0';

    file_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int trace_security_inode_create(
    struct pt_regs *ctx,
    struct inode *dir,
    struct dentry *dentry,
    umode_t mode)
{
    if (!dentry)
        return 0;
    if(submit_inode(ctx, dentry->d_inode, EDGE_CREATE)){
        return 1;
    }
    return 0;
}

int trace_security_inode_setattr(
    struct pt_regs *ctx,
    struct dentry *dentry,
    struct iattr *attr)
{
    if (!dentry)
        return 0;
    if(submit_inode(ctx, dentry->d_inode, EDGE_ATTR)){
        return 1;
    }
    return 0;
}

#include <linux/binfmts.h>

int trace_security_bprm_check(
    struct pt_regs *ctx,
    struct linux_binprm *bprm)
{
    if (!bprm || !bprm->file)
        return 0;
    if(submit_file(ctx, bprm->file, NULL, EDGE_EXEC)){
        return 1;
    }
    return 0;
}



/* ========= DELETE ========= */
/*
int trace_unlinkat(struct tracepoint__syscalls__sys_enter_unlinkat *ctx)
{
    struct file_event_t e = {};

    e.pid  = bpf_get_current_pid_tgid() >> 32;
    e.uid  = bpf_get_current_uid_gid();
    e.edge = EDGE_DELETE;
    e.ts   = bpf_ktime_get_ns();

    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(e.path, sizeof(e.path), ctx->pathname);

    file_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
*/
"""

# =======================
# Load BPF
# =======================

b = BPF(text=program)

b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_execve")
b.attach_tracepoint(tp="syscalls:sys_enter_execveat", fn_name="trace_execveat")
b.attach_tracepoint(tp="syscalls:sys_exit_fork", fn_name="trace_fork_exit")
b.attach_tracepoint(tp="syscalls:sys_exit_vfork", fn_name="trace_vfork_exit")
b.attach_tracepoint(tp="syscalls:sys_exit_clone", fn_name="trace_clone_exit")
b.attach_tracepoint(tp="syscalls:sys_exit_clone3", fn_name="trace_clone3_exit")
b.attach_kprobe(event="security_inode_create",
                fn_name="trace_security_inode_create")

b.attach_kprobe(event="security_inode_setattr",
                fn_name="trace_security_inode_setattr")

b.attach_kprobe(event="security_bprm_check",
                fn_name="trace_security_bprm_check")
#b.attach_tracepoint("syscalls:sys_enter_unlinkat", "trace_unlinkat")

print("Tracing provenance ... Ctrl-C to stop.\n")

# =======================
# Save node to provenance tree
# =======================

def writer_thread():
    with open("Provenance.log", "a") as f:
        while running or not event_queue.empty():
            try:
                line = event_queue.get(timeout=0.5)
                f.write(line + "\n")
                event_queue.task_done()
            except:
                pass

def provstorage(outputstr):
    #with queue
    """
    try:
        event_queue.put_nowait(outputstr)
    except:
        # queue đầy → bỏ event (chấp nhận được)
        pass
    """
    # no queue
    with open("Provenance.log", "a") as f:
        f.write(outputstr + "\n")

# =======================
# Event handlers
# =======================

def handle_exec(cpu, data, size):
    e = cast(data, POINTER(ExecEvent)).contents
    if e.argc == 0:
        return

    argv0 = e.argv[0].value
#    if argv0 not in (b"sudo", b"/usr/bin/sudo"):
#       return

    syscall = "execve" if e.syscall == 1 else "execveat"

    cmdline = " ".join(
        e.argv[i].value.decode(errors="replace")
        for i in range(e.argc)
    )
    outputstr = "EXEC" + "|" + str(syscall) + "|" + str(e.attr.ts) + "|" + str(e.attr.pid) + "|" + str(e.attr.ppid) + "|" + str(e.attr.euid) + "|" + str(e.comm.decode(errors='replace').strip(chr(0))) + "|" + str(cmdline)
    #print(outputstr)
    provstorage(outputstr)
    #print(f"[EXEC] {syscall}")
    #print(f"  TIMESTAMP={e.attr.ts}")
    #print(f"  PID={e.attr.pid} PPID={e.attr.ppid} EUID={e.attr.euid}")
    #print(f"  COMM={e.comm.decode(errors='replace').strip(chr(0))}")
    #print(f"  CMD={cmdline}")

def handle_fork(cpu, data, size):
    e = cast(data, POINTER(ForkEvent)).contents
    t = {1:"fork", 2:"vfork", 3:"clone", 4:"clone3"}[e.type]
    outputstr = str(t.upper()) + "|" + str(e.child_pid) + "|" + str(e.parent.pid) + "|" + str(e.parent.ts)
    #print(outputstr)
    provstorage(outputstr)
    #print(f"[{t.upper()}] {e.parent.pid} -> {e.child_pid}")
    #print(f"  TIMESTAMP={e.parent.ts}")

def handle_file(cpu, data, size):
    e = cast(data, POINTER(FileEvent)).contents
    edge = {
        EDGE_CREATE: "CREATE",
        EDGE_ATTR: "ATTR",
        EDGE_EXEC: "EXEC"
    }.get(e.edge, "?")
    outputstr = str(edge) + "|" + str(e.uid) + "|" + str(e.pid) + "|" + str(e.inode) + "|" + str(e.dev) + "|" + str(e.path.decode(errors='ignore')) + "|" + str(e.comm.decode(errors='ignore'))
    #print(outputstr)
    if "python3" not in e.comm.decode(errors='ignore'):
        provstorage(outputstr)
    #print(f"[{edge}] pid={e.pid} uid={e.uid} "
    #      f"inode={e.inode} dev={e.dev} "
    #      f"path={e.path.decode(errors='ignore')} "
    #      f"comm={e.comm.decode(errors='ignore')}")


b["exec_events"].open_perf_buffer(handle_exec)
b["fork_events"].open_perf_buffer(handle_fork)
b["file_events"].open_perf_buffer(handle_file, page_cnt=64)

# =======================
# Main loop
# =======================

t = Thread(target=writer_thread, daemon=True)
t.start()
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
        #running = False
        #event_queue.join()
        #print("Stopping tracer...")
