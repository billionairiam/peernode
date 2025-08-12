/*
 * mini_container_overlay_full.c
 *
 * Enhanced minimal container runtime that demonstrates:
 *  - OverlayFS mounting (lowerdir + upperdir + workdir -> merged)
 *  - Namespaces: CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWPID, CLONE_NEWNS, CLONE_NEWNET
 *  - pivot_root into the overlay "merged" dir
 *  - cgroup v2 limits (memory + cpu)
 *  - veth pair creation (parent uses `ip`) and moving one end into child's netns
 *  - capability dropping and optional seccomp (libseccomp if linked)
 *
 * Build:
 *   (without seccomp)
 *     gcc -o mini_container_overlay_full mini_container_overlay_full.c
 *
 *   (with seccomp)
 *     gcc -DHAVE_LIBSECCOMP -o mini_container_overlay_full mini_container_overlay_full.c -lseccomp
 *
 * Run (root):
 *   sudo ./mini_container_overlay_full <lowerdir> <upperdir> <workdir> <host_veth_ip/24> <container_ip/24>
 *
 * Example:
 *   sudo ./mini_container_overlay_full /var/lib/images/ubuntu-lower /var/lib/containers/u1/upper \
 *       /var/lib/containers/u1/work 10.0.3.1/24 10.0.3.2/24
 *
 * Notes:
 *  - Requires overlayfs support in kernel, iproute2 `ip` command, cgroup v2 mounted at /sys/fs/cgroup.
 *  - This is an educational demo — not production hardened. Use runc/crun for production.
 */

#define _GNU_SOURCE
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>

#ifndef SYS_pivot_root
#define SYS_pivot_root 155
#endif

static int pivot_root_wrapper(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

static void fatal(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];

struct args_t {
    const char *merged_root;    // overlay merged mountpoint passed to child
    const char *container_ip;   // e.g. "10.0.3.2/24"
    const char *host_veth_ip;   // e.g. "10.0.3.1/24"
    const char *veth_host;      // host veth name
    const char *veth_child;     // child veth name
    char cgroup_name[64];
};

/* Simple helpers */
static int run_cmd(const char *cmd) {
    int rc = system(cmd);
    if (rc != 0) fprintf(stderr, "[run_cmd] '%s' -> rc=%d\n", cmd, rc);
    return rc;
}

static int write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) return -1;
    ssize_t n = write(fd, data, strlen(data));
    close(fd);
    return n == (ssize_t)strlen(data) ? 0 : -1;
}

static void rand_suffix(char *buf, size_t bufsz) {
    const char *chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    srand((unsigned)time(NULL) ^ getpid());
    for (int i = 0; i < 6 && (size_t)i < bufsz - 1; ++i) buf[i] = chars[rand() % (int)strlen(chars)];
    buf[6] = 0;
}

/* Setup overlay mountpoint in parent. Returns path to merged dir (absolute). */
static int setup_overlay(const char *lowerdir, const char *upperdir, const char *workdir, char *merged_out, size_t outlen) {
    // ensure directories exist
    struct stat st;
    if (stat(lowerdir, &st) == -1 || !S_ISDIR(st.st_mode)) { fprintf(stderr, "lowerdir invalid: %s\n", lowerdir); return -1; }
    if (mkdir(upperdir, 0755) == -1 && errno != EEXIST) { perror("mkdir upperdir"); return -1; }
    if (mkdir(workdir, 0755) == -1 && errno != EEXIST) { perror("mkdir workdir"); return -1; }

    char merged[PATH_MAX];
    snprintf(merged, sizeof(merged), "/tmp/overlay_merged_%d", (int)getpid());
    if (mkdir(merged, 0755) == -1 && errno != EEXIST) { perror("mkdir merged"); return -1; }

    char opts[PATH_MAX * 2];
    snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s", lowerdir, upperdir, workdir);

    if (mount("overlay", merged, "overlay", 0, opts) == -1) {
        perror("mount overlay");
        return -1;
    }

    if (realpath(merged, merged_out) == NULL) {
        perror("realpath merged");
        return -1;
    }
    printf("[parent] overlay mounted at %s (opts=%s)\n", merged_out, opts);
    return 0;
}

/* cgroup v2 setup */
static int setup_cgroup_v2(pid_t child_pid, const char *name_suffix) {
    char cgpath[PATH_MAX];
    const char *base = "/sys/fs/cgroup";
    if (access(base, F_OK) != 0) {
        fprintf(stderr, "cgroup v2 not mounted at %s\n", base);
        return -1;
    }
    snprintf(cgpath, sizeof(cgpath), "%s/minict_%s", base, name_suffix);
    if (mkdir(cgpath, 0755) == -1 && errno != EEXIST) { perror("mkdir cgroup"); return -1; }

    // memory.max (bytes) -> 128MB
    char file[PATH_MAX];
    snprintf(file, sizeof(file), "%s/memory.max", cgpath);
    if (write_file(file, "134217728") != 0) fprintf(stderr, "failed set memory.max\n");

    // cpu.max -> 20000 100000 (20%)
    snprintf(file, sizeof(file), "%s/cpu.max", cgpath);
    if (write_file(file, "20000 100000") != 0) fprintf(stderr, "failed set cpu.max\n");

    // add pid
    snprintf(file, sizeof(file), "%s/cgroup.procs", cgpath);
    char pidstr[32]; snprintf(pidstr, sizeof(pidstr), "%d", child_pid);
    if (write_file(file, pidstr) != 0) { fprintf(stderr, "failed add pid to cgroup.procs\n"); return -1; }

    printf("[parent] cgroup created %s and added pid %d\n", cgpath, child_pid);
    return 0;
}

/* network parent: create veth pair and move child end into child's netns */
static int setup_network_parent(pid_t child_pid, const char *veth_host, const char *veth_child, const char *host_ip_with_mask, const char *container_ip_with_mask) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip link add %s type veth peer name %s", veth_host, veth_child);
    if (run_cmd(cmd) != 0) return -1;

    snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", host_ip_with_mask, veth_host);
    if (run_cmd(cmd) != 0) return -1;

    snprintf(cmd, sizeof(cmd), "ip link set %s up", veth_host);
    if (run_cmd(cmd) != 0) return -1;

    snprintf(cmd, sizeof(cmd), "ip link set %s netns %d", veth_child, child_pid);
    if (run_cmd(cmd) != 0) return -1;

    printf("[parent] created veth %s <-> %s and moved %s into netns %d\n", veth_host, veth_child, veth_child, child_pid);
    return 0;
}

/* drop capabilities (simpler approach) */
static void drop_capabilities(void) {
    int drop_caps[] = { CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_MODULE, CAP_SYS_TIME, CAP_SYS_BOOT, CAP_SYS_TTY_CONFIG };
    size_t n = sizeof(drop_caps)/sizeof(drop_caps[0]);
    for (size_t i = 0; i < n; ++i) prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0);
}

#ifdef HAVE_LIBSECCOMP
#include <seccomp.h>
static int apply_seccomp() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return -1; // default allow for this demo
    // For demo keep allow-all; in production you'd install a restrictive filter.
    seccomp_release(ctx);
    return 0;
}
#else
static int apply_seccomp() { return 0; }
#endif

/* child function: pivot_root into merged root, mount /proc, setup net inside, drop caps, exec shell */
static int child_func(void *arg) {
    struct args_t *a = (struct args_t *)arg;
    const char *new_root = a->merged_root;
    char put_old[PATH_MAX];

    printf("[child] pid=%d starting setup (merged=%s)\n", getpid(), new_root);

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) { perror("mount private"); return -1; }

    if (chdir(new_root) == -1) { perror("chdir new root"); return -1; }

    if (mkdir(".pivot_root_old", 0777) == -1 && errno != EEXIST) { perror("mkdir put_old"); return -1; }

    if (pivot_root_wrapper(new_root, ".pivot_root_old") == -1) { perror("pivot_root"); return -1; }

    if (chdir("/") == -1) { perror("chdir /"); return -1; }

    if (umount2("/.pivot_root_old", MNT_DETACH) == -1) { perror("umount2 oldroot"); }
    rmdir("/.pivot_root_old");

    if (mount("proc", "/proc", "proc", MS_NOEXEC | MS_NOSUID | MS_NODEV, NULL) == -1) { perror("mount /proc"); }

    if (mkdir("/dev", 0755) == -1 && errno != EEXIST) { perror("mkdir /dev"); }
    if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=755") == 0) {
        mknod("/dev/null", S_IFCHR | 0666, makedev(1,3));
        mknod("/dev/zero", S_IFCHR | 0666, makedev(1,5));
        mknod("/dev/tty", S_IFCHR | 0666, makedev(5,0));
        mknod("/dev/console", S_IFCHR | 0600, makedev(5,1));
    }

    sethostname("mini-overlay", strlen("mini-overlay"));

    // configure networking inside child using ip from rootfs if present
    const char *ipbin = "/bin/ip";
    if (access(ipbin, X_OK) == 0) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "%s link set lo up", ipbin); system(cmd);
        // rename veth child to eth0
        snprintf(cmd, sizeof(cmd), "%s link set %s name eth0", ipbin, a->veth_child); system(cmd);
        snprintf(cmd, sizeof(cmd), "%s addr add %s dev eth0", ipbin, a->container_ip); system(cmd);
        snprintf(cmd, sizeof(cmd), "%s link set eth0 up", ipbin); system(cmd);
        // default route via host veth ip (strip mask)
        char host_ip_only[64]; strncpy(host_ip_only, a->host_veth_ip, sizeof(host_ip_only)-1);
        char *slash = strchr(host_ip_only, '/'); if (slash) *slash = '\0';
        snprintf(cmd, sizeof(cmd), "%s route add default via %s", ipbin, host_ip_only); system(cmd);
    } else {
        fprintf(stderr, "[child] ip not found in rootfs; skip net config\n");
    }

    drop_capabilities();
    if (apply_seccomp() != 0) fprintf(stderr, "[child] seccomp not applied or failed\n");

    char *const argv[] = { "/bin/sh", NULL };
    execv("/bin/sh", argv);
    perror("execv /bin/sh");
    return -1;
}

int main(int argc, char *argv[]) {
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <lowerdir> <upperdir> <workdir> <host_veth_ip/24> <container_ip/24>\n", argv[0]);
        return 1;
    }
    const char *lowerdir = argv[1];
    const char *upperdir = argv[2];
    const char *workdir = argv[3];
    const char *host_veth_ip = argv[4];
    const char *container_ip = argv[5];

    char merged[PATH_MAX];
    if (setup_overlay(lowerdir, upperdir, workdir, merged, sizeof(merged)) != 0) {
        fprintf(stderr, "failed setup overlay\n"); return 1;
    }

    char suf[8]; rand_suffix(suf, sizeof(suf));
    char veth_host[64], veth_child[64];
    snprintf(veth_host, sizeof(veth_host), "vethh_%s", suf);
    snprintf(veth_child, sizeof(veth_child), "vethc_%s", suf);

    struct args_t a = {0};
    a.merged_root = strdup(merged);
    a.container_ip = container_ip;
    a.host_veth_ip = host_veth_ip;
    a.veth_host = strdup(veth_host);
    a.veth_child = strdup(veth_child);
    snprintf(a.cgroup_name, sizeof(a.cgroup_name), "minict_%s", suf);

    int flags = CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | SIGCHLD;
    pid_t child = clone(child_func, child_stack + STACK_SIZE, flags, &a);
    if (child == -1) fatal("clone");

    printf("[parent] child pid=%d\n", child);

    // setup cgroup and network
    if (setup_cgroup_v2(child, suf) != 0) fprintf(stderr, "[parent] cgroup setup warning\n");
    if (setup_network_parent(child, a.veth_host, a.veth_child, a.host_veth_ip, a.container_ip) != 0) fprintf(stderr, "[parent] network setup warning\n");

    int status;
    if (waitpid(child, &status, 0) == -1) perror("waitpid");
    else printf("[parent] child exited status=%d\n", status);

    // cleanup overlay mountpoint (best-effort)
    char cmd[256]; snprintf(cmd, sizeof(cmd), "umount %s", merged); run_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", merged); run_cmd(cmd);

    return 0;
}
