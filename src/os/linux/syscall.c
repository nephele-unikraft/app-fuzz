#include "syscall.h"
#include "utils.h"

/* From https://gitlab.com/strace/strace/-/blob/master/src/linux/x86_64/syscallent.h */
int os_syscall_params_num[] = {
	3, // "read",
	3, // "write",
	3, // "open",
	1, // "close",
	2, // "stat",
	2, // "fstat",
	2, // "lstat",
	3, // "poll",
	3, // "lseek",
	6, // "mmap",
	3, // "mprotect",
	2, // "munmap",
	1, // "brk",
	4, // "rt_sigaction",
	4, // "rt_sigprocmask",
	0, // "rt_sigreturn",
	3, // "ioctl",
	4, // "pread64",
	4, // "pwrite64",
	3, // "readv",
	3, // "writev",
	2, // "access",
	1, // "pipe",
	5, // "select",
	0, // "sched_yield",
	5, // "mremap",
	3, // "msync",
	3, // "mincore",
	3, // "madvise",
	3, // "shmget",
	3, // "shmat",
	3, // "shmctl",
	1, // "dup",
	2, // "dup2",
	0, // "pause",
	2, // "nanosleep",
	2, // "getitimer",
	1, // "alarm",
	3, // "setitimer",
	0, // "getpid",
	4, // "sendfile",
	3, // "socket",
	3, // "connect",
	3, // "accept",
	6, // "sendto",
	6, // "recvfrom",
	3, // "sendmsg",
	3, // "recvmsg",
	2, // "shutdown",
	3, // "bind",
	2, // "listen",
	3, // "getsockname",
	3, // "getpeername",
	4, // "socketpair",
	5, // "setsockopt",
	5, // "getsockopt",
	5, // "clone",
	0, // "fork",
	0, // "vfork",
	3, // "execve",
	1, // "exit",
	4, // "wait4",
	2, // "kill",
	1, // "uname",
	3, // "semget",
	3, // "semop",
	4, // "semctl",
	1, // "shmdt",
	2, // "msgget",
	4, // "msgsnd",
	5, // "msgrcv",
	3, // "msgctl",
	3, // "fcntl",
	2, // "flock",
	1, // "fsync",
	1, // "fdatasync",
	2, // "truncate",
	2, // "ftruncate",
	3, // "getdents",
	2, // "getcwd",
	1, // "chdir",
	1, // "fchdir",
	2, // "rename",
	2, // "mkdir",
	1, // "rmdir",
	2, // "creat",
	2, // "link",
	1, // "unlink",
	2, // "symlink",
	3, // "readlink",
	2, // "chmod",
	2, // "fchmod",
	3, // "chown",
	3, // "fchown",
	3, // "lchown",
	1, // "umask",
	2, // "gettimeofday",
	2, // "getrlimit",
	2, // "getrusage",
	1, // "sysinfo",
	1, // "times",
	4, // "ptrace",
	0, // "getuid",
	3, // "syslog",
	0, // "getgid",
	1, // "setuid",
	1, // "setgid",
	0, // "geteuid",
	0, // "getegid",
	2, // "setpgid",
	0, // "getppid",
	0, // "getpgrp",
	0, // "setsid",
	2, // "setreuid",
	2, // "setregid",
	2, // "getgroups",
	2, // "setgroups",
	3, // "setresuid",
	3, // "getresuid",
	3, // "setresgid",
	3, // "getresgid",
	1, // "getpgid",
	1, // "setfsuid",
	1, // "setfsgid",
	1, // "getsid",
	2, // "capget",
	2, // "capset",
	2, // "rt_sigpending",
	4, // "rt_sigtimedwait",
	3, // "rt_sigqueueinfo",
	2, // "rt_sigsuspend",
	2, // "sigaltstack",
	2, // "utime",
	3, // "mknod",
	1, // "uselib",
	1, // "personality",
	2, // "ustat",
	2, // "statfs",
	2, // "fstatfs",
	3, // "sysfs",
	2, // "getpriority",
	3, // "setpriority",
	2, // "sched_setparam",
	2, // "sched_getparam",
	3, // "sched_setscheduler",
	1, // "sched_getscheduler",
	1, // "sched_get_priority_max",
	1, // "sched_get_priority_min",
	2, // ),"sched_rr_get_interval",
	2, // "mlock",
	2, // "munlock",
	1, // "mlockall",
	0, // "munlockall",
	0, // "vhangup",
	3, // "modify_ldt",
	2, // "pivot_root",
	1, // "_sysctl",
	5, // "prctl",
	2, // "arch_prctl",
	1, // "adjtimex",
	2, // "setrlimit",
	1, // "chroot",
	0, // "sync",
	1, // "acct",
	2, // "settimeofday",
	5, // "mount",
	2, // "umount2",
	2, // "swapon",
	1, // "swapoff",
	4, // "reboot",
	2, // "sethostname",
	2, // "setdomainname",
	1, // "iopl",
	3, // "ioperm",
	2, // "create_module",
	3, // "init_module",
	2, // "delete_module",
	1, // "get_kernel_syms",
	5, // "query_module",
	4, // "quotactl",
	3, // "nfsservctl",
	5, // "getpmsg",
	5, // "putpmsg",
	5, // "afs_syscall",
	3, // "tuxcall",
	3, // "security",
	0, // "gettid",
	3, // "readahead",
	5, // "setxattr",
	5, // "lsetxattr",
	5, // "fsetxattr",
	4, // "getxattr",
	4, // "lgetxattr",
	4, // "fgetxattr",
	3, // "listxattr",
	3, // "llistxattr",
	3, // "flistxattr",
	2, // "removexattr",
	2, // "lremovexattr",
	2, // "fremovexattr",
	2, // "tkill",
	1, // "time",
	6, // "futex",
	3, // "sched_setaffinity",
	3, // "sched_getaffinity",
	1, // "set_thread_area",
	2, // "io_setup",
	1, // "io_destroy",
	5, // "io_getevents",
	3, // "io_submit",
	3, // "io_cancel",
	1, // "get_thread_area",
	3, // "lookup_dcookie",
	1, // "epoll_create",
	4, // "epoll_ctl_old",
	4, // "epoll_wait_old",
	5, // "remap_file_pages",
	3, // "getdents64",
	1, // "set_tid_address",
	0, // "restart_syscall",
	4, // "semtimedop",
	4, // "fadvise64",
	3, // "timer_create",
	4, // "timer_settime",
	2, // "timer_gettime",
	1, // "timer_getoverrun",
	1, // "timer_delete",
	2, // "clock_settime",
	2, // "clock_gettime",
	2, // "clock_getres",
	4, // "clock_nanosleep",
	1, // "exit_group",
	4, // "epoll_wait",
	4, // "epoll_ctl",
	3, // "tgkill",
	2, // "utimes",
	5, // "vserver",
	6, // "mbind",
	3, // "set_mempolicy",
	5, // "get_mempolicy",
	4, // "mq_open",
	1, // "mq_unlink",
	5, // "mq_timedsend",
	5, // "mq_timedreceive",
	2, // "mq_notify",
	3, // "mq_getsetattr",
	4, // "kexec_load",
	5, // "waitid",
	5, // "add_key",
	4, // "request_key",
	5, // "keyctl",
	3, // "ioprio_set",
	2, // "ioprio_get",
	0, // "inotify_init",
	3, // "inotify_add_watch",
	2, // "inotify_rm_watch",
	4, // "migrate_pages",
	4, // "openat",
	3, // "mkdirat",
	4, // "mknodat",
	5, // "fchownat",
	3, // "futimesat",
	4, // "newfstatat",
	3, // "unlinkat",
	4, // "renameat",
	5, // "linkat",
	3, // "symlinkat",
	4, // "readlinkat",
	3, // "fchmodat",
	3, // "faccessat",
	6, // "pselect6",
	5, // "ppoll",
	1, // "unshare",
	2, // "set_robust_list",
	3, // "get_robust_list",
	6, // "splice",
	4, // "tee",
	4, // "sync_file_range",
	4, // "vmsplice",
	6, // "move_pages",
	4, // "utimensat",
	6, // "epoll_pwait",
	3, // "signalfd",
	2, // "timerfd_create",
	1, // "eventfd",
	4, // "fallocate",
	4, // "timerfd_settime",
	2, // "timerfd_gettime",
	4, // "accept4",
	4, // "signalfd4",
	2, // "eventfd2",
	1, // "epoll_create1",
	3, // "dup3",
	2, // "pipe2",
	1, // "inotify_init1",
	4, // "preadv",
	4, // "pwritev",
	4, // "rt_tgsigqueueinfo",
	5, // "perf_event_open",
	5, // "recvmmsg",
	2, // "fanotify_init",
	5, // "fanotify_mark",
	4, // "prlimit64",
	5, // "name_to_handle_at",
	3, // "open_by_handle_at",
	2, // "clock_adjtime",
	1, // "syncfs",
	4, // "sendmmsg",
	2, // "setns",
	3, // "getcpu",
	6, // "process_vm_readv",
	6, // "process_vm_writev",
	5, // "kcmp",
	3, // "finit_module",
	3, // "sched_setattr",
	4, // "sched_getattr",
	5, // "renameat2",
	3, // "seccomp",
	3, // "getrandom",
	2, // "memfd_create",
	5, // "kexec_file_load",
	3, // "bpf",
	5, // "execveat",
	1, // "userfaultfd",
	3, // "membarrier",
	3, // "mlock2",
	6, // "copy_file_range",
	6, // "preadv2",
	6, // "pwritev2",
	4, // "pkey_mprotect",
	2, // "pkey_alloc",
	1, // "pkey_free",
	5, // "statx",
	6, // "io_pgetevents",
	4, // "rseq",
};

long os_syscall_num(void)
{
	return ARRAY_SIZE(os_syscall_params_num);
}