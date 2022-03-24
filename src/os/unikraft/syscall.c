#include "syscall.h"
#include "utils.h"

int os_syscall_params_num[] = {
	3, /* 0 SYS_read */
	3, /* 1 SYS_write */
	0, /* 2 SYS_open */
	0, /* 3 SYS_close */
	0, /* 4 SYS_stat */
	2, /* 5 SYS_fstat */
	0, /* 6 SYS_lstat */
	0, /* 7 SYS_poll */
	0, /* 8 SYS_lseek */
	0, /* 9 SYS_mmap */
	0, /* 10 SYS_mprotect */
	0, /* 11 SYS_munmap */
	0, /* 12 SYS_brk */
	0, /* 13 SYS_rt_sigaction */
	0, /* 14 SYS_rt_sigprocmask */
	0, /* 15 SYS_rt_sigreturn */
	0, /* 16 SYS_ioctl */
	0, /* 17 SYS_pread64 */
	0, /* 18 SYS_pwrite64 */
	3, /* 19 SYS_readv */
	3, /* 20 SYS_writev */
	0, /* 21 SYS_access */
	0, /* 22 SYS_pipe */
	0, /* 23 SYS_select */
	0, /* 24 SYS_sched_yield */
	0, /* 25 SYS_mremap */
	0, /* 26 SYS_msync */
	0, /* 27 SYS_mincore */
	0, /* 28 SYS_madvise */
	0, /* 29 SYS_shmget */
	0, /* 30 SYS_shmat */
	0, /* 31 SYS_shmctl */
	0, /* 32 SYS_dup */
	0, /* 33 SYS_dup2 */
	0, /* 34 SYS_pause */
	0, /* 35 SYS_nanosleep */
	0, /* 36 SYS_getitimer */
	0, /* 37 SYS_alarm */
	0, /* 38 SYS_setitimer */
	0, /* 39 SYS_getpid */
	0, /* 40 SYS_sendfile */
	0, /* 41 SYS_socket */
	0, /* 42 SYS_connect */
	0, /* 43 SYS_accept */
	0, /* 44 SYS_sendto */
	0, /* 45 SYS_recvfrom */
	0, /* 46 SYS_sendmsg */
	0, /* 47 SYS_recvmsg */
	0, /* 48 SYS_shutdown */
	0, /* 49 SYS_bind */
	0, /* 50 SYS_listen */
	0, /* 51 SYS_getsockname */
	0, /* 52 SYS_getpeername */
	0, /* 53 SYS_socketpair */
	0, /* 54 SYS_setsockopt */
	0, /* 55 SYS_getsockopt */
	0, /* 56 SYS_clone */
	0, /* 57 SYS_fork */
	0, /* 58 SYS_vfork */
	0, /* 59 SYS_execve */
	0, /* 60 SYS_exit */
	0, /* 61 SYS_wait4 */
	0, /* 62 SYS_kill */
	1, /* 63 SYS_uname */
	0, /* 64 SYS_semget */
	0, /* 65 SYS_semop */
	0, /* 66 SYS_semctl */
	0, /* 67 SYS_shmdt */
	0, /* 68 SYS_msgget */
	0, /* 69 SYS_msgsnd */
	0, /* 70 SYS_msgrcv */
	0, /* 71 SYS_msgctl */
	0, /* 72 SYS_fcntl */
	0, /* 73 SYS_flock */
	0, /* 74 SYS_fsync */
	0, /* 75 SYS_fdatasync */
	0, /* 76 SYS_truncate */
	0, /* 77 SYS_ftruncate */
	0, /* 78 SYS_getdents */
	0, /* 79 SYS_getcwd */
	0, /* 80 SYS_chdir */
	0, /* 81 SYS_fchdir */
	0, /* 82 SYS_rename */
	0, /* 83 SYS_mkdir */
	0, /* 84 SYS_rmdir */
	0, /* 85 SYS_creat */
	0, /* 86 SYS_link */
	0, /* 87 SYS_unlink */
	0, /* 88 SYS_symlink */
	3, /* 89 SYS_readlink */
	0, /* 90 SYS_chmod */
	0, /* 91 SYS_fchmod */
	0, /* 92 SYS_chown */
	0, /* 93 SYS_fchown */
	0, /* 94 SYS_lchown */
	0, /* 95 SYS_umask */
	0, /* 96 SYS_gettimeofday */
	0, /* 97 SYS_getrlimit */
	0, /* 98 SYS_getrusage */
	0, /* 99 SYS_sysinfo */
	0, /* 100 SYS_times */
	0, /* 101 SYS_ptrace */
	0, /* 102 SYS_getuid */
	0, /* 103 SYS_syslog */
	0, /* 104 SYS_getgid */
	0, /* 105 SYS_setuid */
	0, /* 106 SYS_setgid */
	0, /* 107 SYS_geteuid */
	0, /* 108 SYS_getegid */
	0, /* 109 SYS_setpgid */
	0, /* 110 SYS_getppid */
	0, /* 111 SYS_getpgrp */
	0, /* 112 SYS_setsid */
	0, /* 113 SYS_setreuid */
	0, /* 114 SYS_setregid */
	0, /* 115 SYS_getgroups */
	0, /* 116 SYS_setgroups */
	0, /* 117 SYS_setresuid */
	0, /* 118 SYS_getresuid */
	0, /* 119 SYS_setresgid */
	0, /* 120 SYS_getresgid */
	0, /* 121 SYS_getpgid */
	0, /* 122 SYS_setfsuid */
	0, /* 123 SYS_setfsgid */
	0, /* 124 SYS_getsid */
	0, /* 125 SYS_capget */
	0, /* 126 SYS_capset */
	0, /* 127 SYS_rt_sigpending */
	0, /* 128 SYS_rt_sigtimedwait */
	0, /* 129 SYS_rt_sigqueueinfo */
	0, /* 130 SYS_rt_sigsuspend */
	0, /* 131 SYS_sigaltstack */
	0, /* 132 SYS_utime */
	0, /* 133 SYS_mknod */
	0, /* 134 SYS_uselib */
	0, /* 135 SYS_personality */
	0, /* 136 SYS_ustat */
	0, /* 137 SYS_statfs */
	0, /* 138 SYS_fstatfs */
	0, /* 139 SYS_sysfs */
	0, /* 140 SYS_getpriority */
	0, /* 141 SYS_setpriority */
	0, /* 142 SYS_sched_setparam */
	0, /* 143 SYS_sched_getparam */
	0, /* 144 SYS_sched_setscheduler */
	0, /* 145 SYS_sched_getscheduler */
	0, /* 146 SYS_sched_get_priority_max */
	0, /* 147 SYS_sched_get_priority_min */
	0, /* 148 SYS_sched_rr_get_interval */
	0, /* 149 SYS_mlock */
	0, /* 150 SYS_munlock */
	0, /* 151 SYS_mlockall */
	0, /* 152 SYS_munlockall */
	0, /* 153 SYS_vhangup */
	0, /* 154 SYS_modify_ldt */
	0, /* 155 SYS_pivot_root */
	0, /* 156 SYS__sysctl */
	0, /* 157 SYS_prctl */
	0, /* 158 SYS_arch_prctl */
	0, /* 159 SYS_adjtimex */
	0, /* 160 SYS_setrlimit */
	0, /* 161 SYS_chroot */
	0, /* 162 SYS_sync */
	0, /* 163 SYS_acct */
	0, /* 164 SYS_settimeofday */
	0, /* 165 SYS_mount */
	0, /* 166 SYS_umount2 */
	0, /* 167 SYS_swapon */
	0, /* 168 SYS_swapoff */
	0, /* 169 SYS_reboot */
	0, /* 170 SYS_sethostname */
	0, /* 171 SYS_setdomainname */
	0, /* 172 SYS_iopl */
	0, /* 173 SYS_ioperm */
	0, /* 174 SYS_create_module */
	0, /* 175 SYS_init_module */
	0, /* 176 SYS_delete_module */
	0, /* 177 SYS_get_kernel_syms */
	0, /* 178 SYS_query_module */
	0, /* 179 SYS_quotactl */
	0, /* 180 SYS_nfsservctl */
	0, /* 181 SYS_getpmsg */
	0, /* 182 SYS_putpmsg */
	0, /* 183 SYS_afs_syscall */
	0, /* 184 SYS_tuxcall */
	0, /* 185 SYS_security */
	0, /* 186 SYS_gettid */
	0, /* 187 SYS_readahead */
	0, /* 188 SYS_setxattr */
	0, /* 189 SYS_lsetxattr */
	0, /* 190 SYS_fsetxattr */
	0, /* 191 SYS_getxattr */
	0, /* 192 SYS_lgetxattr */
	0, /* 193 SYS_fgetxattr */
	0, /* 194 SYS_listxattr */
	0, /* 195 SYS_llistxattr */
	0, /* 196 SYS_flistxattr */
	0, /* 197 SYS_removexattr */
	0, /* 198 SYS_lremovexattr */
	0, /* 199 SYS_fremovexattr */
	0, /* 200 SYS_tkill */
	0, /* 201 SYS_time */
	0, /* 202 SYS_futex */
	0, /* 203 SYS_sched_setaffinity */
	0, /* 204 SYS_sched_getaffinity */
	0, /* 205 SYS_set_thread_area */
	0, /* 206 SYS_io_setup */
	0, /* 207 SYS_io_destroy */
	0, /* 208 SYS_io_getevents */
	0, /* 209 SYS_io_submit */
	0, /* 210 SYS_io_cancel */
	0, /* 211 SYS_get_thread_area */
	0, /* 212 SYS_lookup_dcookie */
	0, /* 213 SYS_epoll_create */
	0, /* 214 SYS_epoll_ctl_old */
	0, /* 215 SYS_epoll_wait_old */
	0, /* 216 SYS_remap_file_pages */
	0, /* 217 SYS_getdents64 */
	0, /* 218 SYS_set_tid_address */
	0, /* 219 SYS_restart_syscall */
	0, /* 220 SYS_semtimedop */
	0, /* 221 SYS_fadvise64 */
	0, /* 222 SYS_timer_create */
	0, /* 223 SYS_timer_settime */
	0, /* 224 SYS_timer_gettime */
	0, /* 225 SYS_timer_getoverrun */
	0, /* 226 SYS_timer_delete */
	0, /* 227 SYS_clock_settime */
	0, /* 228 SYS_clock_gettime */
	0, /* 229 SYS_clock_getres */
	0, /* 230 SYS_clock_nanosleep */
	0, /* 231 SYS_exit_group */
	0, /* 232 SYS_epoll_wait */
	0, /* 233 SYS_epoll_ctl */
	0, /* 234 SYS_tgkill */
	0, /* 235 SYS_utimes */
	0, /* 236 SYS_vserver */
	0, /* 237 SYS_mbind */
	0, /* 238 SYS_set_mempolicy */
	0, /* 239 SYS_get_mempolicy */
	0, /* 240 SYS_mq_open */
	0, /* 241 SYS_mq_unlink */
	0, /* 242 SYS_mq_timedsend */
	0, /* 243 SYS_mq_timedreceive */
	0, /* 244 SYS_mq_notify */
	0, /* 245 SYS_mq_getsetattr */
	0, /* 246 SYS_kexec_load */
	0, /* 247 SYS_waitid */
	0, /* 248 SYS_add_key */
	0, /* 249 SYS_request_key */
	0, /* 250 SYS_keyctl */
	0, /* 251 SYS_ioprio_set */
	0, /* 252 SYS_ioprio_get */
	0, /* 253 SYS_inotify_init */
	0, /* 254 SYS_inotify_add_watch */
	0, /* 255 SYS_inotify_rm_watch */
	0, /* 256 SYS_migrate_pages */
	0, /* 257 SYS_openat */
	0, /* 258 SYS_mkdirat */
	0, /* 259 SYS_mknodat */
	0, /* 260 SYS_fchownat */
	0, /* 261 SYS_futimesat */
	0, /* 262 SYS_newfstatat */
	0, /* 263 SYS_unlinkat */
	0, /* 264 SYS_renameat */
	0, /* 265 SYS_linkat */
	0, /* 266 SYS_symlinkat */
	0, /* 267 SYS_readlinkat */
	0, /* 268 SYS_fchmodat */
	0, /* 269 SYS_faccessat */
	0, /* 270 SYS_pselect6 */
	0, /* 271 SYS_ppoll */
	0, /* 272 SYS_unshare */
	0, /* 273 SYS_set_robust_list */
	0, /* 274 SYS_get_robust_list */
	0, /* 275 SYS_splice */
	0, /* 276 SYS_tee */
	0, /* 277 SYS_sync_file_range */
	0, /* 278 SYS_vmsplice */
	0, /* 279 SYS_move_pages */
	0, /* 280 SYS_utimensat */
	0, /* 281 SYS_epoll_pwait */
	0, /* 282 SYS_signalfd */
	0, /* 283 SYS_timerfd_create */
	0, /* 284 SYS_eventfd */
	0, /* 285 SYS_fallocate */
	0, /* 286 SYS_timerfd_settime */
	0, /* 287 SYS_timerfd_gettime */
	0, /* 288 SYS_accept4 */
	0, /* 289 SYS_signalfd4 */
	0, /* 290 SYS_eventfd2 */
	0, /* 291 SYS_epoll_create1 */
	0, /* 292 SYS_dup3 */
	0, /* 293 SYS_pipe2 */
	0, /* 294 SYS_inotify_init1 */
	0, /* 295 SYS_preadv */
	0, /* 296 SYS_pwritev */
	0, /* 297 SYS_rt_tgsigqueueinfo */
	0, /* 298 SYS_perf_event_open */
	0, /* 299 SYS_recvmmsg */
	0, /* 300 SYS_fanotify_init */
	0, /* 301 SYS_fanotify_mark */
	0, /* 302 SYS_prlimit64 */
	0, /* 303 SYS_name_to_handle_at */
	0, /* 304 SYS_open_by_handle_at */
	0, /* 305 SYS_clock_adjtime */
	0, /* 306 SYS_syncfs */
	0, /* 307 SYS_sendmmsg */
	0, /* 308 SYS_setns */
	0, /* 309 SYS_getcpu */
	0, /* 310 SYS_process_vm_readv */
	0, /* 311 SYS_process_vm_writev */
	0, /* 312 SYS_kcmp */
	0, /* 313 SYS_finit_module */
	0, /* 314 SYS_sched_setattr */
	0, /* 315 SYS_sched_getattr */
	0, /* 316 SYS_renameat2 */
	0, /* 317 SYS_seccomp */
	0, /* 318 SYS_getrandom */
	0, /* 319 SYS_memfd_create */
	0, /* 320 SYS_kexec_file_load */
	0, /* 321 SYS_bpf */
	0, /* 322 SYS_execveat */
	0, /* 323 SYS_userfaultfd */
	0, /* 324 SYS_membarrier */
	0, /* 325 SYS_mlock2 */
	0, /* 326 SYS_copy_file_range */
	0, /* 327 SYS_preadv2 */
	0, /* 328 SYS_pwritev2 */
	0, /* 329 SYS_pkey_mprotect */
	0, /* 330 SYS_pkey_alloc */
	0, /* 331 SYS_pkey_free */
	0, /* 332 SYS_statx */
	0, /* 333 SYS_io_pgetevents */
	0, /* 334 SYS_rseq */
};

long os_syscall_num(void)
{
	return ARRAY_SIZE(os_syscall_params_num);
}