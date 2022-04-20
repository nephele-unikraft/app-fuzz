#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include "os.h"
#include "syscall_fuzzing.h"
#include "utils.h"


static int do_close_stdin;

static void print_usage(char *cmd)
{
    fprintf(stderr, "Usage: %s [OPTION]..\n", cmd);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "-h, --help                    Display this help and exit\n");
    fprintf(stderr, "-r, --write-ready             Write ready in Xenstore\n");
    fprintf(stderr, "-t, --trace-syscalls          Trace syscalls\n");
    fprintf(stderr, "-b, --baseline                Run baseline (fuzz a single no-crash syscall)\n");
    fprintf(stderr, "-c, --close-stdin             Close stdin\n");
}

static int parse_args(int argc, char **argv)
{
    int opt, opt_index, rc = 0;
    const char *short_opts = "hrtbc";
    const struct option long_opts[] = {
        { "help"               , no_argument       , NULL , 'h' },
        { "write-ready   "     , no_argument       , NULL , 'r' },
        { "trace-syscalls"     , no_argument       , NULL , 't' },
        { "baseline"           , no_argument       , NULL , 'b' },
        { "close-stdin"        , no_argument       , NULL , 'c' },
        { NULL , 0 , NULL , 0 }
    };

    while (1) {
        opt = getopt_long(argc, argv, short_opts, long_opts, &opt_index);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            exit(0);
            break;

        case 'r':
            do_write_ready = 1;
            break;

        case 't':
            do_trace_syscalls = 1;
            break;

        case 'b':
            do_baseline = 1;
            break;

        case 'c':
            do_close_stdin = 1;
            break;

        default:
            rc = -1;
            break;
        }
    }

    while (optind < argc) {
        ERROR("%s: invalid argument \'%s\'\n", argv[0], argv[optind]);
        rc = -1;
        optind++;
    }

    if (rc) {
        print_usage(argv[0]);
        exit(rc);
    }

    return rc;
}

int main(int argc, char* argv[])
{
	int rc;

	/* Parse arguments */
	rc = parse_args(argc, argv);
	if (rc) {
		ERROR("Error calling os_parse_args() rc=%d\n", rc);
		goto out;
	}

	if (do_close_stdin)
		close(STDIN_FILENO);

	rc = os_fuzz_init();
	if (rc) {
		ERROR("Error os_fuzz_init()=%d\n", rc);
		goto out;
	}

	rc = (int) os_fuzz();
	if (rc) {
		ERROR("Error os_fuzz()=%d\n", rc);
		goto out;
	}

out:
	return rc;
}
