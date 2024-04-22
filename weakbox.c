#define _GNU_SOURCE
#include "arg.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#define LEN(arr) (sizeof(arr) / sizeof(*arr))
#define mapping_t(type) \
	struct {            \
		type source;    \
		type target;    \
	}

#define DEBUG(...) (flagv ? fprintf(stderr, __VA_ARGS__) : 0)

#define SET_MAPPING_WITH_DEMILITER(mapping, argf, temp, demiliter, source_, target_) \
	if (((temp) = strchr(argf, demiliter))) {                                        \
		*(temp)++        = '\0';                                                     \
		(mapping).source = source_;                                                  \
		(mapping).target = target_;                                                  \
	} else {                                                                         \
		(mapping).source = source_;                                                  \
		(mapping).target = source_;                                                  \
	}

#define PATH_PROC_UIDMAP    "/proc/self/uid_map"
#define PATH_PROC_GIDMAP    "/proc/self/gid_map"
#define PATH_PROC_SETGROUPS "/proc/self/setgroups"
#define SHELL_DEFAULT       "bash"
#define MAX_BINDS           64
#define MAX_USERMAP         8
#define MAX_GROUPMAP        16


static int open_printf(const char* file, const char* format, ...) {
	FILE*   fd;
	va_list va;

	if (!(fd = fopen(file, "w"))) {
		return -1;
	}

	va_start(va, format);
	vfprintf(fd, format, va);
	va_end(va);
	fclose(fd);
	return 0;
}

static char* argv0;

static __attribute__((noreturn)) void usage(int exitcode) {
	printf("usage: %s [-hs] [-r path] [-b source[:target]] [-B source] [-u uid[:uid]] [-g gid[:gid]] command ...\n", argv0);
	exit(exitcode);
}

static int bind_count                         = 9;
static mapping_t(const char*) bind[MAX_BINDS] = {
	{ "/dev", "/dev" },
	{ "/home", "/home" },
	{ "/proc", "/proc" },
	{ "/sys", "/sys" },
	{ "/tmp", "/tmp" },
	{ "/run", "/run" },
	{ "/etc/resolv.conf", "/etc/resolv.conf" },
	{ "/etc/passwd", "/etc/passwd" },
	{ "/etc/group", "/etc/group" }
};

static int usermap_count = 0;
static mapping_t(uid_t) usermap[MAX_USERMAP];

static int groupmap_count = 0;
static mapping_t(gid_t) groupmap[MAX_GROUPMAP];

static int remove_bind(const char* path) {
	int found = 0;
	for (int i = 0; i < bind_count; i++) {
		if (!strcmp(bind[i].source, path))
			found++, bind_count--;
		if (found) {
			bind[i].source = bind[i + 1].source;
			bind[i].target = bind[i + 1].target;
		}
	}
	return found;
}

int main(int argc, char** argv) {
	const char* root  = getenv("WEAKBOX");
	const char* shell = getenv("SHELL");
	int         flagr = 0, flagv = 0;
	char        pwd[PATH_MAX];
	char*       temp;
	char*       argf;

	(void) argc;

	getcwd(pwd, sizeof(pwd));

	argv0 = *argv;
	ARGBEGIN
	switch (OPT) {
		case 'h':
			usage(0);
		case 'v':
			flagv++;
			break;
		case 's':
			flagr++;
			break;
		case 'r':
			root = EARGF(usage(1));
			break;
		case 'b':
			argf = EARGF(usage(1));
			if (bind_count >= (int) LEN(bind)) {
				printf("error: too many bindings\n");
				return 1;
			}
			SET_MAPPING_WITH_DEMILITER(bind[bind_count], argf, temp, ':', argf, temp);
			bind_count++;
			break;
		case 'u':
			argf = EARGF(usage(1));
			if (usermap_count >= (int) LEN(usermap)) {
				printf("error: too many user-mappings\n");
				return 1;
			}

			SET_MAPPING_WITH_DEMILITER(usermap[usermap_count], argf, temp, ':', atoi(argf), atoi(temp));
			usermap_count++;
			break;
		case 'g':
			argf = EARGF(usage(1));
			if (groupmap_count >= (int) LEN(groupmap)) {
				printf("error: too many group-mappings\n");
				return 1;
			}
			SET_MAPPING_WITH_DEMILITER(groupmap[groupmap_count], argf, temp, ':', atoi(argf), atoi(temp));
			groupmap_count++;
			break;
		case 'B':
			argf = EARGF(usage(1));
			if (!remove_bind(argf))
				printf("warn: binding '%s' not found\n", argf);
			break;
		default:
			printf("error: unknown option '-%c'\n", OPT);
			usage(1);
	}
	ARGEND

	usermap[usermap_count].source     = flagr ? geteuid() : 0;
	usermap[usermap_count++].target   = geteuid();
	groupmap[groupmap_count].source   = flagr ? getegid() : 0;
	groupmap[groupmap_count++].target = getegid();

	if (!root) {
		fprintf(stderr, "error: $WEAKBOX not set and option '-r' is not used\n");
		return 1;
	}

	DEBUG("debug: unsharing filesystem-namespace and user-namespace\n");
	if (unshare(CLONE_NEWNS | CLONE_NEWUSER)) {
		fprintf(stderr, "error: unable to unshare for new filesystem and user-environment: %s\n", strerror(errno));
		return 1;
	}

	DEBUG("debug: setting setgroups-policy\n");
	if (open_printf(PATH_PROC_SETGROUPS, "deny") && errno != ENOENT) {
		fprintf(stderr, "error: unable to set setgroups-policy: %s\n", strerror(errno));
		return 1;
	}

	for (int i = 0; i < usermap_count; i++) {
		DEBUG("debug: mapping user %d to %d\n", usermap[i].source, usermap[i].target);
		if (open_printf(PATH_PROC_UIDMAP, "%u %u 1", usermap[i].source, usermap[i].target)) {
			fprintf(stderr, "error: unable to map user %d to %d: %s\n", usermap[i].source, usermap[i].target, strerror(errno));
			return 1;
		}
	}

	for (int i = 0; i < groupmap_count; i++) {
		DEBUG("debug: mapping group %d to %d\n", groupmap[i].source, groupmap[i].target);
		if (open_printf(PATH_PROC_GIDMAP, "%u %u 1", groupmap[i].source, groupmap[i].target)) {
			fprintf(stderr, "error: unable to map group %d to %d: %s\n", groupmap[i].source, groupmap[i].target, strerror(errno));
			return 1;
		}
	}

	char target[PATH_MAX];
	for (int i = 0; i < bind_count; i++) {
		snprintf(target, sizeof(target), "%s/%s", root, bind[i].target);
		DEBUG("debug: mount '%s' to '%s'\n", bind[i].source, target);
		if (mount(bind[i].source, target, NULL, MS_BIND | MS_REC, NULL)) {
			fprintf(stderr, "error: unable to bind '%s' to '%s': %s\n", bind[i].source, target, strerror(errno));
			return 1;
		}
	}

	DEBUG("debug: change root to '%s'\n", root);
	if (chroot(root)) {
		fprintf(stderr, "error: unable to set root to '%s': %s\n", root, strerror(errno));
		return 1;
	}

	// if chdir(pwd) fails, chdir("/") cannot fail
	DEBUG("debug: change directory to '%s'\n", pwd);
	if (chdir(pwd)) {
		DEBUG("debug: ... which failed (%s), change directory to '/'\n", strerror(errno));
		(void) chdir("/");
	}

	if (*argv) {
		DEBUG("debug: executing '%s'...\n", *argv);
		execvp(*argv, argv);
		fprintf(stderr, "error: unable to execute '%s': %s\n", *argv, strerror(errno));
	} else if (shell) {
		DEBUG("debug: executing '%s'...\n", shell);
		execlp(shell, shell, NULL);
		execlp(SHELL_DEFAULT, SHELL_DEFAULT, NULL);
		fprintf(stderr, "error: unable to execute '%s' or '" SHELL_DEFAULT "': %s\n", shell, strerror(errno));
	}
	return 1;
}
