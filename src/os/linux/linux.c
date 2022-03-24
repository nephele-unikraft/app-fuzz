#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "syscall_fuzzing.h"
#include "utils.h"


#if defined(FZ_LINUX_MODULE)
static inline void harness(void)
{
	unsigned int tmp;

	asm volatile ("cpuid"
			: "=a" (tmp)
			: "a" (0x13371337)
			: "bx", "cx", "dx");
}

static inline void harness_extended(unsigned int magic, void *a, size_t s)
{
	unsigned int high = (unsigned long)a >> 32;

	asm volatile ("cpuid"
			: "=a" (magic)
			: "a" (magic), "c" (s)
			: "bx", "dx");
	asm volatile ("cpuid"
			: "=a" (magic)
			: "a" (high), "c" (a)
			: "bx", "dx");
}
#endif

long os_fuzz(void)
{
	long rc = 0;

	//msleep(3000);
#if defined(FZ_LINUX_MODULE)
	harness_extended(0x13371337, &gCall, sizeof(gCall));
#endif

	rc = syscall_fuzzing_exec();
	INFO("SYSCALL RET: %ld \n", rc);

#if defined(FZ_LINUX_MODULE)
	harness();
#endif

	return rc;
}

int os_fuzz_init(void)
{
	int rc;

	printf("gCall address: %p\n gCall size: %ld\n", &gCall, sizeof(gCall));

	rc = read(STDIN_FILENO, &gCall, sizeof(gCall));
	if (rc != sizeof(gCall)) {
		fprintf(stderr, "read()=%d\n", rc);
		rc = -1;
	}

	return rc;
}
