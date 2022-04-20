#include <string.h>
#include "os.h"
#include "syscall_fuzzing.h"
#include "utils.h"


static uint32_t fuzzed_syscall_ids[] = {
			0, /* read */
			1, /* write */
			5, /* fstat */
			19, /* sys_readv */
			20, /* sys_writev */
			63, /* sys_uname */
			89, /* sys_readlink */
};

call_t gCall;

int do_write_ready;
int do_trace_syscalls;
int do_baseline;

#define __SYSCALL_TRACE(params_num, id, pCall) \
do { \
	if (do_trace_syscalls) { \
		fprintf(stderr, "syscall=%u id=%u ", id, pCall->id); \
		for (int i = 0; i < params_num; i++) \
			fprintf(stderr, "param%d=%x ", i, *(&pCall->p.param0 + i)); \
		fprintf(stderr, "\n"); \
	} \
} while (0)

#define SYSCALL_TRACE(params_num, id, pCall) \
	/*__SYSCALL_TRACE(params_num, id, pCall);*/ \
	__SYSCALL_TRACE(6, id, pCall)


static long exec_syscall_0(uint32_t id, call_t *pCall)
{
	long rc;

	SYSCALL_TRACE(0, id, pCall);

	rc = OS_SYSCALL(id);

	return rc;
}

static long exec_syscall_1(uint32_t id, call_t * pCall)
{
	long rc;

	SYSCALL_TRACE(1, id, pCall);

	rc = OS_SYSCALL(id, pCall->p.param0);

	return rc;
}

static long exec_syscall_2(uint32_t id, call_t *pCall)
{
	long rc;

	SYSCALL_TRACE(2, id, pCall);

	rc = OS_SYSCALL(id, pCall->p.param0, pCall->p.param1);

	return rc;
}

static long exec_syscall_3(uint32_t id, call_t *pCall)
{
	long rc;

	SYSCALL_TRACE(3, id, pCall);

	rc = OS_SYSCALL(id, pCall->p.param0, pCall->p.param1, pCall->p.param2);

	return rc;
}

static long exec_syscall_4(uint32_t id, call_t *pCall)
{
	long rc;

	SYSCALL_TRACE(4, id, pCall);

	rc = OS_SYSCALL(id, pCall->p.param0, pCall->p.param1, pCall->p.param2,
			pCall->p.param3);

	return rc;
}

static long exec_syscall_5(uint32_t id, call_t *pCall)
{
	long rc;

	SYSCALL_TRACE(5, id, pCall);

	rc = OS_SYSCALL(id, pCall->p.param0, pCall->p.param1, pCall->p.param2,
			pCall->p.param3, pCall->p.param4);

	return rc;
}

static long exec_syscall_6(uint32_t id, call_t *pCall)
{
	long rc;

	SYSCALL_TRACE(6, id, pCall);

	rc = OS_SYSCALL(id, pCall->p.param0, pCall->p.param1, pCall->p.param2,
			pCall->p.param3, pCall->p.param4, pCall->p.param5);

	return rc;
}

static uint32_t convert_syscall_id(uint32_t syscall_id)
{
	return fuzzed_syscall_ids[(syscall_id % os_syscall_num()) % ARRAY_SIZE(fuzzed_syscall_ids)];
}

static long exec_syscall(call_t *pCall)
{
	uint32_t id;
	long rc;

	if (do_baseline)
		id = SYS_getppid;
	else
		id = convert_syscall_id(pCall->id);

	switch (os_syscall_params_num[id]) {
	case 0:
		rc = exec_syscall_0(id, pCall);
		break;
	case 1:
		rc = exec_syscall_1(id, pCall);
		break;
	case 2:
		rc = exec_syscall_2(id, pCall);
		break;
	case 3:
		rc = exec_syscall_3(id, pCall);
		break;
	case 4:
		rc = exec_syscall_4(id, pCall);
		break;
	case 5:		
		rc = exec_syscall_5(id, pCall);
		break;
	case 6:
		rc = exec_syscall_6(id, pCall);
		break;
	default:
		DEBUG("Default\n");
		rc = 0xBDBDBDBDUL;
	};

	return rc;
}

long syscall_fuzzing_exec(void)
{
	return exec_syscall(&gCall);
}
