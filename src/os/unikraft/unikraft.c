#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <uk/errptr.h>
#include <profile.h>
#include <xenbus/xs.h>
#include <xenbus/client.h>
#include "syscall_fuzzing.h"
#include "utils.h"


#if 0
int network_fd;
static int send_network(void)
{
	network_fd = socket(PF_INET, SOCK_STREAM, 0);

	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));

	server_addr.sin_port = htons(PORT);
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("10.8.0.1");

	int rc = connect(network_fd, (struct sockaddr*) &server_addr,
			sizeof(server_addr));
	if (rc) {
		fprintf(stderr, "connect failed\n");
		return -1;
	}

	char seconds[100];
	char nseconds[100];
	struct timespec start;
	clock_gettime(CLOCK_REALTIME, &start);

	write(network_fd, &start, sizeof(struct timespec));
	return 0;
}
#endif


#ifdef DO_WRITE_BOOT_TIMESTAMP
static int xs_write_timestamp(const char *dir)
{
	struct timespec start;
	int rc;

	rc = clock_gettime(CLOCK_REALTIME, &start);
	if (rc) {
		uk_pr_err("Error calling clock_gettime() rc=%d\n", rc);
		goto out;
	}

	rc = xs_printf(XBT_NIL, dir, "seconds", "%lu", start.tv_sec);
	if (rc) {
		uk_pr_err("Error calling xs_printf() rc=%d\n", rc);
		goto out;
	}

	rc = xs_printf(XBT_NIL, dir, "nseconds", "%lu", start.tv_nsec);
	if (rc) {
		uk_pr_err("Error calling xs_printf() rc=%d\n", rc);
		goto out;
	}

out:
	return rc;
}
#endif

/*
 * KFX needs to know when the VM has completed its p2m mapping in order to
 * access it, so we need a way to notify KFX when this happens. We choose to
 * use Xenstore for communication, thus "ready" means that the p2m mapping is
 * ready to be accessed by KFX.
 */

static int write_ready_xs(void)
{
	char *dir = "data", *node = "trigger-harness";
	int rc;

	PROFILE_NESTED_TICK();

	rc = xs_write(XBT_NIL, dir, node, "ready");
	if (rc) {
		uk_pr_err("Error calling xs_write() rc=%d\n", rc);
		goto out;
	}

	PROFILE_NESTED_TOCK_MSEC("write_ready_xs");
out:
	return rc;
}

static int wait_harness_trigger(void)
{
	char *dir = "data", *node = "trigger-harness", *path, *value = NULL;
	struct xenbus_watch *watch = NULL;
	int rc;

#ifdef DO_WRITE_BOOT_TIMESTAMP
	rc = xs_write_timestamp(dir);
	if (rc) {
		uk_pr_err("Error calling xs_write_timestamp() rc=%d\n", rc);
		return -1;
	}
#endif

	if (do_write_ready)
		write_ready_xs();

	rc = asprintf(&path, "%s/%s", dir, node);
	if (rc <= 0) {
		uk_pr_err("Failed to format back_state_path: %d\n", rc);
		goto out;
	}

	/* create a local watch */
	watch = xs_watch_path(XBT_NIL, path);
	if (PTRISERR(watch)) {
		uk_pr_err("Could not register watch for path=%s\n", path);
		rc = PTR2ERR(watch);
		goto out;
	}

	DEBUG("waiting harness trigger\n");
	for (;;) {
		value = xs_read(XBT_NIL, dir, node);
		if (value && !PTRISERR(value) && !strcmp(value, "done"))
			break;
		xenbus_watch_wait_event(watch);
	}

out:
	if (watch)
		xs_unwatch(XBT_NIL, watch);
	if (path)
		free(path);

	return rc;
}

extern int ukplat_harness(void);

static inline int harness(void)
{
	int rc;

	rc = ukplat_harness();
	DEBUG("ukplat_harness()=%d\n", rc);
	return rc;
}

long os_fuzz(void)
{
	long rc = 0;

	/* Wait Harness */
	wait_harness_trigger();

	DEBUG("harnessing start \n");
	harness();
	DEBUG("harnessed start \n");

	/* Exec syscall */
	rc = syscall_fuzzing_exec();
	/*fprintf(stderr, "SYSCALL RET: %d \n", rc);*/

	DEBUG("harnessing stop \n");
	harness();
	DEBUG("harnessed stop \n");

	return rc;
}

int os_fuzz_init(void)
{
	INFO("Kernel Fuzzer Test Module gCall %p size %ld \n",
			&gCall, sizeof(gCall));
	return 0;
}
