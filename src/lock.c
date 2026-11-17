// gom-lock: applies the final locks inside bubblewrap, right before untrusted code runs.
//
//   gom-lock [--quiet] [--nproc N] [--write PATH]... [--exec PATH]... [--dev PATH]... -- COMMAND [ARG]...
//
// 1. no_new_privs : setuid binaries can no longer raise privileges.
// 2. Landlock     : writes only below --write dirs, execve only below --exec dirs,
//                   device ioctls only below --dev; no abstract sockets or signals
//                   that leave the sandbox domain.
// 3. seccomp      : shrinks kernel attack surface (ptrace, bpf, io_uring, userns, mount, ...),
//                   blocks clone() with namespace flags, risky socket families and TIOCSTI.
// 4. rlimits      : no core dumps; at most --nproc processes/threads (fork bombs stay inside).
// Every step is fail-closed: if anything fails, COMMAND is never executed.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "syscalls.h"

#ifndef TIOCLINUX
#define TIOCLINUX 0x541C
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif
#define X32_BIT 0x40000000u

static int quiet;

static void die(const char *what) {
    fprintf(stderr, "gom-lock: error: %s: %s (command not executed)\n", what, strerror(errno));
    exit(126);
}

/* ---------------------------------------------------------------- Landlock */

static int ll_abi(void) {
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    return abi < 0 ? 0 : (int)abi;
}

static void ll_rule(int rs, const char *path, uint64_t access) {
    if (!access) return;
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) { if (!quiet) fprintf(stderr, "gom-lock: note: %s missing, rule skipped\n", path); return; }
    struct stat st;
    if (fstat(fd, &st)) die(path);
    if (!S_ISDIR(st.st_mode)) {
        /* Landlock rejects directory-only rights on a non-directory: keep the file rights only. */
        uint64_t file_rights = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_EXECUTE |
                               LANDLOCK_ACCESS_FS_READ_FILE;
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
        file_rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
        file_rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif
        access &= file_rights;
        if (!access) { close(fd); return; }
    }
    struct landlock_path_beneath_attr pb = { .allowed_access = access, .parent_fd = fd };
    if (syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0)) die(path);
    close(fd);
}

static void apply_landlock(char **wr, int nwr, char **ex, int nex, char **dv, int ndv) {
    int abi = ll_abi();
    if (abi < 1) { errno = ENOSYS; die("Landlock is not available in this kernel"); }

    uint64_t write = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                     LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR |
                     LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                     LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_SYM;
    uint64_t mknod = LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_BLOCK; /* never granted */
    uint64_t ioctl_dev = 0;
    if (abi >= 2) write |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) write |= LANDLOCK_ACCESS_FS_TRUNCATE;
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
    if (abi >= 5) ioctl_dev = LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif
    struct landlock_ruleset_attr ra = {
        .handled_access_fs = write | mknod | ioctl_dev | LANDLOCK_ACCESS_FS_EXECUTE,
    };
    size_t size = offsetof(struct landlock_ruleset_attr, handled_access_net);
#ifdef LANDLOCK_SCOPE_SIGNAL
    if (abi >= 6) {
        ra.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;
        size = sizeof ra;
    }
#endif
    int rs = (int)syscall(SYS_landlock_create_ruleset, &ra, size, 0);
    if (rs < 0) die("landlock_create_ruleset");
    for (int i = 0; i < nwr; i++) ll_rule(rs, wr[i], write);
    for (int i = 0; i < nex; i++) ll_rule(rs, ex[i], LANDLOCK_ACCESS_FS_EXECUTE);
    for (int i = 0; i < ndv; i++) ll_rule(rs, dv[i], ioctl_dev | write);
    if (syscall(SYS_landlock_restrict_self, rs, 0)) die("landlock_restrict_self");
    close(rs);
    if (!quiet) fprintf(stderr, "gom-lock: Landlock ABI %d active%s\n", abi, abi >= 6 ? " (incl. abstract-socket + signal scoping)" : "");
}

/* ---------------------------------------------------------------- seccomp */

static struct sock_filter prog[512];
static unsigned short n;

static void emit(struct sock_filter f) {
    if (n >= sizeof prog / sizeof *prog) { errno = E2BIG; die("seccomp program too long"); }
    prog[n++] = f;
}
#define LOAD(off)       emit((struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (off)))
#define RET(k)          emit((struct sock_filter)BPF_STMT(BPF_RET | BPF_K, (k)))
#define JEQ(k, t, f)    emit((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (k), (t), (f)))
#define JSET(k, t, f)   emit((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, (k), (t), (f)))
#define JGE(k, t, f)    emit((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (k), (t), (f)))
#define ALLOW           SECCOMP_RET_ALLOW
#define ERR(e)          (SECCOMP_RET_ERRNO | ((e) & SECCOMP_RET_DATA))
#define NR              offsetof(struct seccomp_data, nr)
#define ARG_LO(i)       offsetof(struct seccomp_data, args[i])   /* little endian: low 32 bits */

static void arch_block(const unsigned int *deny, size_t ndeny, unsigned int nr_clone,
                       unsigned int nr_clone3, unsigned int nr_socket, unsigned int nr_ioctl, int is64) {
    LOAD(NR);
    if (is64) { JGE(X32_BIT, 0, 1); RET(ERR(ENOSYS)); }          /* x32 ABI disabled */
    for (size_t i = 0; i < ndeny; i++) { JEQ(deny[i], 0, 1); RET(ERR(EPERM)); }
    /* clone3 flags live in user memory and cannot be filtered: ENOSYS makes glibc fall back to clone. */
    JEQ(nr_clone3, 0, 1); RET(ERR(ENOSYS));
    /* clone: no new namespaces (flags are argument 0 on both ABIs). */
    JEQ(nr_clone, 0, 4);
    LOAD(ARG_LO(0));
    JSET(CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER |
         CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWTIME, 0, 1);
    RET(ERR(EPERM));
    RET(ALLOW);
    /* socket: only UNIX, INET, INET6, NETLINK (the network namespace only has lo anyway). */
    JEQ(nr_socket, 0, 7);
    LOAD(ARG_LO(0));
    JEQ(AF_UNIX, 4, 0);
    JEQ(AF_INET, 3, 0);
    JEQ(AF_INET6, 2, 0);
    JEQ(AF_NETLINK, 1, 0);
    RET(ERR(EAFNOSUPPORT));
    RET(ALLOW);
    /* ioctl: the kernel truncates cmd to 32 bits, so comparing the low word is exact. */
    JEQ(nr_ioctl, 0, 5);
    LOAD(ARG_LO(1));
    JEQ(TIOCSTI, 1, 0);
    JEQ(TIOCLINUX, 0, 1);
    RET(ERR(EPERM));
    RET(ALLOW);
    RET(ALLOW);
}

static void patch_jf(unsigned short at) {
    unsigned int d = n - at - 1;
    if (d > 255) { errno = E2BIG; die("seccomp jump distance"); }
    prog[at].jf = (unsigned char)d;
}

static void apply_seccomp(void) {
    LOAD(offsetof(struct seccomp_data, arch));
    unsigned short skip64 = n; JEQ(AUDIT_ARCH_X86_64, 0, 0);   /* jf patched below */
    arch_block(denied64, sizeof denied64 / sizeof *denied64, NR64_CLONE, NR64_CLONE3, NR64_SOCKET, NR64_IOCTL, 1);
    patch_jf(skip64);
    unsigned short skip32 = n; JEQ(AUDIT_ARCH_I386, 0, 0);
    arch_block(denied32, sizeof denied32 / sizeof *denied32, NR32_CLONE, NR32_CLONE3, NR32_SOCKET, NR32_IOCTL, 0);
    patch_jf(skip32);
    RET(SECCOMP_RET_KILL_PROCESS);                               /* unknown architecture */

    struct sock_fprog fp = { .len = n, .filter = prog };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fp)) die("loading seccomp filter");
    if (!quiet) fprintf(stderr, "gom-lock: seccomp active (%u insns, %zu+%zu denied syscalls)\n", n,
                        sizeof denied64 / sizeof *denied64, sizeof denied32 / sizeof *denied32);
}

/* ---------------------------------------------------------------- main */

int main(int argc, char **argv) {
    char **wr = calloc(argc, sizeof *wr), **ex = calloc(argc, sizeof *ex), **dv = calloc(argc, sizeof *dv);
    int nwr = 0, nex = 0, ndv = 0, i = 1;
    long nproc = 0;
    if (!wr || !ex || !dv) die("calloc");
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { i++; break; }
        if (!strcmp(argv[i], "--quiet")) { quiet = 1; continue; }
        if (i + 1 >= argc) break;
        if (!strcmp(argv[i], "--write")) wr[nwr++] = argv[++i];
        else if (!strcmp(argv[i], "--exec")) ex[nex++] = argv[++i];
        else if (!strcmp(argv[i], "--dev")) dv[ndv++] = argv[++i];
        else if (!strcmp(argv[i], "--nproc")) {
            char *end; nproc = strtol(argv[++i], &end, 10);
            if (*end || nproc < 1) { fprintf(stderr, "gom-lock: bad --nproc %s\n", argv[i]); return 2; }
        }
        else { fprintf(stderr, "gom-lock: unknown option %s\n", argv[i]); return 2; }
    }
    if (i >= argc) {
        fprintf(stderr, "usage: gom-lock [--quiet] [--nproc N] [--write P]... [--exec P]... [--dev P]... -- COMMAND [ARG]...\n");
        return 2;
    }

    struct rlimit zero = { 0, 0 };
    if (setrlimit(RLIMIT_CORE, &zero)) die("RLIMIT_CORE");
    if (nproc) {
        struct rlimit lim = { (rlim_t)nproc, (rlim_t)nproc };
        if (setrlimit(RLIMIT_NPROC, &lim)) die("RLIMIT_NPROC");
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) die("no_new_privs");
    apply_landlock(wr, nwr, ex, nex, dv, ndv);
    apply_seccomp();
    execvp(argv[i], &argv[i]);
    die(argv[i]);
}
