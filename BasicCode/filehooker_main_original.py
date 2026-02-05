from bcc import BPF
from ctypes import *
import sys

# =======================
# Constants
# =======================

PATH_LEN = 256

REL_READ  = 1
REL_WRITE = 2

# =======================
# Python-side structure
# =======================

class FileEvent(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("ppid", c_uint),
        ("uid", c_uint),
        ("gid", c_uint),

        ("inode", c_ulonglong),
        ("owner_uid", c_uint),
        ("owner_gid", c_uint),

        ("relationship", c_uint),
        ("name", c_char * PATH_LEN),
        ("ts", c_ulonglong),
    ]


# =======================
# eBPF program (BCC LSM)
# =======================

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/cred.h>

#define NAME_LEN 64

#define REL_READ  1
#define REL_WRITE 2

struct file_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;

    u64 inode;
    u32 owner_uid;
    u32 owner_gid;

    u32 relationship;
    char name[NAME_LEN];
    u64 ts;
};

BPF_PERF_OUTPUT(file_events);

static inline int fill_file_attr(
    struct file_event_t *e,
    struct file *file)
{
    struct inode *inode;
    struct dentry *dentry;

    if (!file)
        return -1;

    inode = file->f_inode;
    if (!inode)
        return -1;

    e->inode = inode->i_ino;
    e->owner_uid = inode->i_uid.val;
    e->owner_gid = inode->i_gid.val;

    dentry = file->f_path.dentry;
    if (dentry)
        bpf_probe_read_kernel_str(
            e->name, sizeof(e->name),
            dentry->d_name.name
        );

    return 0;
}

/* kprobe on LSM hook */
int kprobe__security_file_open(struct pt_regs *ctx, struct file *file)
{
    struct file_event_t e = {};
    struct task_struct *task;
    u64 uidgid;

    task = (struct task_struct *)bpf_get_current_task();

    e.pid  = bpf_get_current_pid_tgid() >> 32;
    e.ppid = task->real_parent->tgid;

    uidgid = bpf_get_current_uid_gid();
    e.uid = uidgid & 0xffffffff;
    e.gid = uidgid >> 32;

    e.ts = bpf_ktime_get_ns();

    if (file->f_mode & FMODE_WRITE)
        e.relationship = REL_WRITE;
    else
        e.relationship = REL_READ;

    if (fill_file_attr(&e, file) < 0)
        return 0;

    file_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

# =======================
# Load BPF
# =======================

b = BPF(text=program)
print("Tracing file provenance edges (LSM, BCC)... Ctrl-C to stop.\n")

# =======================
# Event handler
# =======================

def handle_file(cpu, data, size):
    e = cast(data, POINTER(FileEvent)).contents

    rel = "WRITE" if e.relationship == REL_WRITE else "READ"

    print("[FILE]")
    print(f"  PID={e.pid} PPID={e.ppid}")
    print(f"  UID={e.uid} GID={e.gid}")
    print(f"  INODE={e.inode}")
    print(f"  OWNER={e.owner_uid}:{e.owner_gid}")
    print(f"  REL={rel}")
    print(f"  NAME={e.name.decode(errors='replace')}")
    print()

b["file_events"].open_perf_buffer(handle_file)

# =======================
# Main loop
# =======================

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
