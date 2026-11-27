// attack: behaves like a malicious game inside the gom cage and tries every common trick.
// Only ever run through `gom --selftest`. It never targets anything outside the cage on
// purpose: every "escape" it attempts is expected to fail, and the host-side checks in
// gom verify that nothing leaked.
//
// Output: "BLOCKED  ..." for a barrier that held, "OPEN!!   ..." for one that did not,
//         "info     ..." for compatibility facts. Last line: RESULT all-blocked | RESULT OPEN <n>
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <net/if.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static int open_count;
long mount_try(void);

static void verdict(int blocked, const char *what, int err) {
    if (blocked) printf("BLOCKED  %-58s (%s)\n", what, err ? strerror(err) : "denied");
    else { printf("OPEN!!   %s\n", what); open_count++; }
    fflush(stdout);
}
static void info(const char *fmt, const char *s) { printf("info     "); printf(fmt, s); printf("\n"); fflush(stdout); }

/* A raw syscall that must fail with exactly the expected errno. */
static void must_fail(const char *what, long r, int expect) {
    int e = errno;
    verdict(r == -1 && (expect == 0 || e == expect), what, r == -1 ? e : 0);
}

static const char *env_or(const char *k, const char *d) { const char *v = getenv(k); return v && *v ? v : d; }

/* ------------------------------------------------------------- 1. stealing files */

static void steal(void) {
    const char *home = env_or("GOM_HOST_HOME", "/home/user");
    const char *targets[] = { ".ssh/id_ed25519", ".ssh/id_rsa", ".ssh", ".zsh_history", ".bash_history",
        ".librewolf", ".mozilla", ".config/chromium", ".config/discord", ".local/share/Steam",
        ".aws", ".config/gh/hosts.yml", ".gnupg", ".config/pulse/cookie", ".Xauthority",
        ".local/share/keyrings", "Downloads", "Documents", ".claude.json", NULL };
    char p[4096], msg[4200];
    for (int i = 0; targets[i]; i++) {
        snprintf(p, sizeof p, "%s/%s", home, targets[i]);
        int fd = open(p, O_RDONLY | O_CLOEXEC);
        int e = errno;
        snprintf(msg, sizeof msg, "read ~/%s", targets[i]);
        verdict(fd < 0, msg, e);
        if (fd >= 0) close(fd);
    }
    int fd = open("/etc/shadow", O_RDONLY); verdict(fd < 0, "read /etc/shadow", errno); if (fd >= 0) close(fd);
    char buf[512] = {0};
    fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) { if (read(fd, buf, sizeof buf - 1) < 0) buf[0] = 0; close(fd); }
    const char *real_user = env_or("GOM_HOST_USER", "\x01");
    char needle[300]; snprintf(needle, sizeof needle, "\n%s:", real_user);
    char padded[600]; snprintf(padded, sizeof padded, "\n%s", buf);
    verdict(!strstr(padded, needle) && !strstr(buf, "root:x:0"), "learn real user names from /etc/passwd", 0);
    char host[256] = {0}; gethostname(host, sizeof host - 1);
    verdict(strcmp(host, "gom") == 0, "learn real hostname", 0);
}

/* ------------------------------------------------------------- 2. network / exfiltration */

static void network(void) {
    struct addrinfo *ai = NULL, hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    int r = getaddrinfo("example.com", "443", &hints, &ai);
    verdict(r != 0, "DNS lookup example.com", 0);
    if (ai) freeaddrinfo(ai);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(443) };
    inet_pton(AF_INET, "1.1.1.1", &a.sin_addr);
    r = s >= 0 ? connect(s, (struct sockaddr *)&a, sizeof a) : -1;
    verdict(r < 0, "TCP connect 1.1.1.1:443 (C2 / exfiltration)", errno);
    if (s >= 0) close(s);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    a.sin_port = htons(53); inet_pton(AF_INET, "8.8.8.8", &a.sin_addr);
    r = s >= 0 ? (int)sendto(s, "x", 1, 0, (struct sockaddr *)&a, sizeof a) : -1;
    verdict(r < 0, "UDP send 8.8.8.8:53", errno);
    if (s >= 0) close(s);

    s = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_port = htons(443) };
    inet_pton(AF_INET6, "2606:4700:4700::1111", &a6.sin6_addr);
    r = s >= 0 ? connect(s, (struct sockaddr *)&a6, sizeof a6) : -1;
    verdict(r < 0, "TCP connect over IPv6", errno);
    if (s >= 0) close(s);

    struct if_nameindex *ifs = if_nameindex(), *i;
    int other = 0;
    for (i = ifs; i && i->if_name; i++) if (strcmp(i->if_name, "lo")) other++;
    if (ifs) if_freenameindex(ifs);
    verdict(other == 0, "see any network interface besides lo", 0);
}

/* ------------------------------------------------------------- 3. desktop: keylogging, D-Bus */

static int unix_connect(const char *path, int abstract) {
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_un u = { .sun_family = AF_UNIX };
    socklen_t len;
    if (abstract) { u.sun_path[0] = 0; strncpy(u.sun_path + 1, path, sizeof u.sun_path - 2); len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(path); }
    else { strncpy(u.sun_path, path, sizeof u.sun_path - 1); len = sizeof u; }
    int r = connect(s, (struct sockaddr *)&u, len);
    int e = errno; close(s); errno = e;
    return r;
}

static void desktop(void) {
    const char *hd = env_or("GOM_HOST_DISPLAY", ":0");
    const char *num = strchr(hd, ':'); num = num ? num + 1 : "0";
    char p[256], msg[320];
    snprintf(p, sizeof p, "/tmp/.X11-unix/X%.*s", (int)strcspn(num, "."), num);
    snprintf(msg, sizeof msg, "connect host X server %s (keylogger, screenshots)", p);
    int r = unix_connect(p, 0); verdict(r < 0, msg, errno);
    snprintf(msg, sizeof msg, "connect host X server via abstract @%s", p);
    r = unix_connect(p, 1); verdict(r < 0, msg, errno);

    const char *rt = env_or("GOM_HOST_RUNTIME", "/run/user/1000");
    snprintf(p, sizeof p, "%s/bus", rt);
    r = unix_connect(p, 0); verdict(r < 0, "connect session D-Bus (notifications, secrets, portals)", errno);
    r = unix_connect("/run/dbus/system_bus_socket", 0); verdict(r < 0, "connect system D-Bus", errno);
    snprintf(p, sizeof p, "%s/pipewire-0", rt);
    r = unix_connect(p, 0); verdict(r < 0, "connect PipeWire (screen capture, camera)", errno);
    r = unix_connect("/var/run/docker.sock", 0); verdict(r < 0, "connect docker socket", errno);

    const char *disp = getenv("DISPLAY");
    if (disp) info("own display is %s (gamescope's private Xwayland)", disp);
}

/* ------------------------------------------------------------- 4. audio: microphone, modules */

static int run_cmd(const char *cmd, char *out, size_t n) {
    FILE *f = popen(cmd, "r");
    if (!f) return -1;
    size_t got = fread(out, 1, n - 1, f); out[got] = 0;
    int st = pclose(f);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void audio(void) {
    if (!getenv("PULSE_SERVER")) { info("%s", "audio disabled for this run"); return; }
    char out[8192];
    if (run_cmd("pactl list short sources 2>&1", out, sizeof out) != 0) { info("pactl failed: %s", out); return; }
    verdict(!strstr(out, "alsa_input") && !strstr(out, "bluez") && !strstr(out, "alsa_output"),
            "see a microphone or the real sound card", 0);
    int r = run_cmd("pactl list short cards 2>&1", out, sizeof out);
    verdict(r != 0 || strlen(out) == 0, "see sound card hardware", 0);
    r = run_cmd("pactl load-module module-pipe-sink file=/tmp/gom-pipe 2>&1", out, sizeof out);
    verdict(r != 0, "load a PulseAudio module (writes host files, opens TCP)", 0);
    r = run_cmd("pactl load-module module-native-protocol-tcp 2>&1", out, sizeof out);
    verdict(r != 0, "open a network listener through the audio server", 0);
    r = run_cmd("timeout 2 parecord --raw -d game.monitor /dev/null 2>&1; echo $?", out, sizeof out);
    info("recording the game's own output is possible (harmless): exit %s", out);
}

/* ------------------------------------------------------------- 5. privilege escalation surface */

static void kernel(void) {
    must_fail("ptrace(TRACEME) (debugger-based injection)", ptrace(PTRACE_TRACEME, 0, 0, 0), EPERM);
    must_fail("ptrace(ATTACH, pid 1)", ptrace(PTRACE_ATTACH, 1, 0, 0), EPERM);
    char b[8]; struct iovec l = { b, sizeof b }, rm = { b, sizeof b };
    must_fail("process_vm_readv (read another process' memory)", syscall(SYS_process_vm_readv, 1, &l, 1, &rm, 1, 0), EPERM);
    must_fail("unshare(CLONE_NEWUSER) (fake root, unlock netfilter etc.)", unshare(CLONE_NEWUSER), EPERM);
    must_fail("unshare(CLONE_NEWNS)", unshare(CLONE_NEWNS), EPERM);
    must_fail("clone(CLONE_NEWUSER)", syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0), EPERM);
    struct clone_args ca = { .flags = CLONE_NEWUSER, .exit_signal = SIGCHLD };
    must_fail("clone3(CLONE_NEWUSER)", syscall(SYS_clone3, &ca, sizeof ca), ENOSYS);
    must_fail("bpf()", syscall(SYS_bpf, 0, 0, 0), EPERM);
    must_fail("perf_event_open()", syscall(SYS_perf_event_open, 0, 0, -1, -1, 0), EPERM);
    must_fail("userfaultfd() (classic exploit primitive)", syscall(SYS_userfaultfd, 0), EPERM);
    must_fail("io_uring_setup() (frequent LPE source)", syscall(SYS_io_uring_setup, 1, 0), EPERM);
    must_fail("keyctl()", syscall(SYS_keyctl, 0, 0, 0, 0, 0), EPERM);
    must_fail("add_key()", syscall(SYS_add_key, "user", "x", "y", 1, 0), EPERM);
    must_fail("init_module() (load kernel code)", syscall(SYS_init_module, 0, 0, ""), EPERM);
    must_fail("mount()", mount_try(), EPERM);
    must_fail("kexec_load()", syscall(SYS_kexec_load, 0, 0, 0, 0), EPERM);
    must_fail("open_by_handle_at() (shocker-style escape)", syscall(SYS_open_by_handle_at, AT_FDCWD, 0, 0), EPERM);
    must_fail("setns()", syscall(SYS_setns, 0, 0), EPERM);
    must_fail("chroot()", chroot("/tmp"), EPERM);
    must_fail("x32 ABI syscall (filter bypass attempt)", syscall(0x40000000 | SYS_getpid), ENOSYS);

    long r;
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(26L), "b"(0L), "c"(0L), "d"(0L) : "memory");   /* i386 ptrace */
    verdict(r == -EPERM, "i386 ABI ptrace via int 0x80 (filter bypass attempt)", r < 0 ? (int)-r : 0);
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(310L), "b"((long)CLONE_NEWUSER) : "memory");     /* i386 unshare */
    verdict(r == -EPERM, "i386 ABI unshare(CLONE_NEWUSER) via int 0x80", r < 0 ? (int)-r : 0);

    int fams[] = { AF_PACKET, AF_VSOCK, AF_ALG, AF_BLUETOOTH, AF_KEY, AF_TIPC, AF_RDS, AF_XDP };
    const char *names[] = { "AF_PACKET", "AF_VSOCK", "AF_ALG", "AF_BLUETOOTH", "AF_KEY", "AF_TIPC", "AF_RDS", "AF_XDP" };
    char msg[96];
    for (unsigned i = 0; i < sizeof fams / sizeof *fams; i++) {
        int s = socket(fams[i], SOCK_RAW, 0);
        snprintf(msg, sizeof msg, "socket(%s)", names[i]);
        verdict(s < 0, msg, errno);
        if (s >= 0) close(s);
    }
    char c = 'x';
    must_fail("TIOCSTI (type commands into your terminal)", ioctl(0, TIOCSTI, &c), EPERM);
    must_fail("TIOCSTI with high bits set (filter bypass attempt)", syscall(SYS_ioctl, 0, 0x100000000UL | TIOCSTI, &c), EPERM);

    verdict(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "regain privileges through setuid binaries", 0);
    if (access("/usr/bin/sudo", X_OK) == 0) {
        char out[256] = {0};
        run_cmd("/usr/bin/sudo -n id -u 2>/dev/null", out, sizeof out);
        verdict(strncmp(out, "0", 1) != 0, "become root with sudo", 0);
    }
    char st[4096] = {0}; int fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) { if (read(fd, st, sizeof st - 1) < 0) st[0] = 0; close(fd); }
    char *ce = strstr(st, "CapEff:");
    verdict(ce && strstr(ce, "0000000000000000") == ce + 8, "hold any Linux capability", 0);
}

long mount_try(void);
long mount_try(void) { return syscall(SYS_mount, "none", "/tmp", "tmpfs", 0, 0); }

/* ------------------------------------------------------------- 6. persistence / tampering */

static int try_write(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;
    int r = write(fd, data, strlen(data)) < 0 ? -1 : 0;
    close(fd);
    return r;
}

static void persistence(void) {
    const char *home = getenv("HOME");
    char p[4096];
    must_fail("write into /usr/bin (trojan a system binary)", try_write("/usr/bin/gom-evil", "x"), 0);
    must_fail("write into /etc", try_write("/etc/gom-evil", "x"), 0);
    must_fail("write to / root", try_write("/gom-evil", "x"), 0);
    must_fail("create a device node", mknod("/tmp/gom-dev", S_IFCHR | 0666, makedev(1, 3)), 0);

    /* These succeed, but only inside the cage: gom's host-side checks prove nothing leaked. */
    snprintf(p, sizeof p, "%s/.config", home); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/.config/autostart", home); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/.config/autostart/evil.desktop", home);
    info("autostart entry written to private home: %s", try_write(p, "[Desktop Entry]\nExec=evil\n") == 0 ? "yes" : "no");
    snprintf(p, sizeof p, "%s/.zshrc", home);
    try_write(p, "# gom-selftest\n");
    try_write("/tmp/gom-selftest-escape", "x");
    info("writing the game's own folder works (overlay): %s", try_write("/game/written-by-game", "x") == 0 ? "yes" : "no");
    try_write("/game/marker.txt", "tampered\n");

    /* Drop-and-execute a second stage from a writable place. */
    int in = open("/usr/bin/true", O_RDONLY), out = open("/tmp/stage2", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    char buf[65536]; ssize_t k;
    while (in >= 0 && out >= 0 && (k = read(in, buf, sizeof buf)) > 0) if (write(out, buf, k) != k) break;
    if (in >= 0) close(in);
    if (out >= 0) close(out);
    pid_t pid = fork();
    if (pid == 0) { char *av[] = { "/tmp/stage2", NULL }; execv(av[0], av); _exit(errno == EACCES ? 77 : 78); }
    int ws = 0; waitpid(pid, &ws, 0);
    /* Not a barrier: installers need it, and the game folder is writable + executable anyway. */
    info("dropped binary in /tmp runs (still inside the cage, no new rights): %s",
         WIFEXITED(ws) && WEXITSTATUS(ws) == 0 ? "yes" : "no");

    /* Host file handles inherited through bwrap (e.g. gom's profile lock) must not reach the game. */
    int leaked = 0; DIR *fds = opendir("/proc/self/fd"); struct dirent *fe;
    while (fds && (fe = readdir(fds))) {
        int n = atoi(fe->d_name);
        if (fe->d_name[0] < '0' || fe->d_name[0] > '9' || n <= 2 || n == dirfd(fds)) continue;
        char lp[64], tgt[512] = {0};
        snprintf(lp, sizeof lp, "/proc/self/fd/%d", n);
        if (readlink(lp, tgt, sizeof tgt - 1) < 0) continue;
        printf("info     inherited fd %d -> %s\n", n, tgt);
        leaked++;
    }
    if (fds) closedir(fds);
    verdict(leaked == 0, "use file handles leaked from the host", 0);
}

/* ------------------------------------------------------------- 7. visibility */

static void visibility(void) {
    int procs = 0; DIR *d = opendir("/proc"); struct dirent *e;
    while (d && (e = readdir(d))) if (e->d_name[0] >= '0' && e->d_name[0] <= '9') procs++;
    if (d) closedir(d);
    verdict(procs < 16, "see host processes in /proc", 0);
    const char *devs[] = { "/dev/input", "/dev/snd", "/dev/kvm", "/dev/dri/card0", "/dev/video0", "/dev/hidraw0", "/dev/sda", "/dev/nvme0n1", "/dev/mem", NULL };
    char msg[96];
    for (int i = 0; devs[i]; i++) {
        snprintf(msg, sizeof msg, "access %s", devs[i]);
        verdict(access(devs[i], F_OK) != 0, msg, errno);
    }
    int fd = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC);
    info("GPU render node usable (needed for speed): %s", fd >= 0 ? "yes" : "no");
    if (fd >= 0) close(fd);
    void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    info("JIT memory works (Java/Mono/Lua games): %s", m != MAP_FAILED ? "yes" : "no");
}

/* ------------------------------------------------------------- 8. second-stage tricks / limits */

static void tricks(void) {
    /* Fileless execution: copy a binary into an anonymous memfd and execute it. */
    int in = open("/usr/bin/true", O_RDONLY), mfd = (int)syscall(SYS_memfd_create, "x", 0);
    char buf[65536]; ssize_t k;
    while (in >= 0 && mfd >= 0 && (k = read(in, buf, sizeof buf)) > 0) if (write(mfd, buf, k) != k) break;
    if (in >= 0) close(in);
    pid_t pid = fork();
    if (pid == 0) {
        char *av[] = { "x", NULL }, *ev[] = { NULL };
        syscall(SYS_execveat, mfd, "", av, ev, AT_EMPTY_PATH);
        _exit(errno == EACCES ? 77 : 78);
    }
    int ws = 0; waitpid(pid, &ws, 0);
    /* Not a barrier: the game already runs arbitrary native code (JIT memory must stay allowed), so a
       second program gains nothing. It runs inside the same cage with the same restrictions. */
    info("fileless exec from memfd works (still inside the cage, no new rights): %s",
         WIFEXITED(ws) && WEXITSTATUS(ws) == 0 ? "yes" : "no");
    if (mfd >= 0) close(mfd);

    /* ld.so trick: run a dropped binary via the dynamic loader. Landlock cannot see mmap(PROT_EXEC),
       so this works, but it still runs INSIDE the cage with exactly the same restrictions. */
    pid = fork();
    if (pid == 0) {
        int dn = open("/dev/null", O_WRONLY); dup2(dn, 1); dup2(dn, 2);
        char *av[] = { "/lib64/ld-linux-x86-64.so.2", "/tmp/stage2", NULL };
        execv(av[0], av); _exit(99);
    }
    waitpid(pid, &ws, 0);
    info("ld.so can run a dropped binary (still inside the cage): %s", WIFEXITED(ws) && WEXITSTATUS(ws) == 0 ? "yes" : "no");

    struct rlimit rl;
    getrlimit(RLIMIT_NPROC, &rl);
    verdict(rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur <= 8192 && rl.rlim_max == rl.rlim_cur,
            "fork bomb that freezes the host (unlimited processes)", 0);
    getrlimit(RLIMIT_CORE, &rl);
    verdict(rl.rlim_max == 0, "core dumps of the game's memory to disk", 0);
    struct rlimit up = { RLIM_INFINITY, RLIM_INFINITY };
    must_fail("raise its own process limit back", setrlimit(RLIMIT_NPROC, &up), EPERM);

    /* The host sound server must be unreachable from every cage. */
    const char *rt = env_or("GOM_HOST_RUNTIME", "/run/user/1000");
    char p[256]; snprintf(p, sizeof p, "%s/pulse/native", rt);
    if (strcmp(p, "/run/user/1000/pulse/native") && strcmp(p, "/run/user/0/pulse/native")) {
        int r = unix_connect(p, 0); verdict(r < 0, "connect host PulseAudio", errno);
    }
    int r = unix_connect("/audio/out", 0); verdict(r < 0, "reach the audio cage's FIFO", errno);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("=== attack simulation inside gom (uid %d) ===\n", getuid());
    printf("--- 1. stealing files\n");        steal();
    printf("--- 2. network\n");               network();
    printf("--- 3. desktop session\n");       desktop();
    printf("--- 4. audio\n");                 audio();
    printf("--- 5. kernel / privileges\n");   kernel();
    printf("--- 6. persistence\n");           persistence();
    printf("--- 7. visibility\n");            visibility();
    printf("--- 8. second stage / limits\n"); tricks();
    if (open_count) printf("RESULT OPEN %d\n", open_count);
    else printf("RESULT all-blocked\n");
    return open_count ? 1 : 0;
}
