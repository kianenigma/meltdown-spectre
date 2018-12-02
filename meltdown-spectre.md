# Meltdown and Spectre. 

[Both attacks](https://meltdownattack.com/) have been discovered in parallel in early 2018 and exploit all Intel CPUs, having an _out-of-order_ execution logic unit. This makes the impact of the attack drastically wide, making many of the devices produced after ~2012 vulnerable (of course there are both software and hardware mitigations). 

Both attacks can be used to leak memory from privileged memory regions. In fact, the authors of Meltdown prove that it can be used to dump the entire DRAM. In the attached code, of course, I will not try to read any sensitive data but leak a local string variable.

```c
const char *test = "TestStringLeakedByMeltdown";
```

Nonetheless, this is still enough as a proof of concept since this local variable is never read directly. In fact, in the `meltdown.c` file it is even not in the same function as the attack function. 

Both attacks use the same concept: The privilege check off the CPU happens after optimization. Hence, even though an illegal access will NEVER be reflected to the attacker in code, it will have micro-architectural effects on hardware that can later be used to leak information. In both of these attacks, the target address (assume it is a kernel memory address) is used to address a page offset in a huge chunk of heap memory. Later on, a cache [Flush+Reload attack](https://eprint.iacr.org/2013/448.pdf) is performed to check which page of the memory chunk is cached and effectively read the restricted target address. 

### How-To-Run

The `makefile` provided should be enough to compile both codes for any **Linux-Like** OS (does NOT work on MacOS' CLang, not tested in Windows). Apologies for the warnings. You really cannot expect an attack code to be compiler-friendly, right? 

### Meltdown 

The internal Logic is pretty simple: 

- attempt to read a target address that you do NOT have access to and use it as an array index, and create a signal handler to catch the segfault and prevent crash. 

```
char temp = probe_buffer[(*(volatile char *)_target_addr) * 4 * KB];
```

- When returned from the segfault handler to the main code (via a `longjmp()`), the target memory address is not read of course and we cannot access it. But no worries.
- Because of the out-of-order-execution optimization of the CPU, the CPU was kind enough to read the target address for you, *before the privilege check was complete*. In fact the CPU has probably already executed the entire line of the above code snipper before the privilege check.
- The CPU then reverts the out-of-order-execution read and removes all side effects except for the fact that the page (`4*KB`) at offset `*_target_addr` of the `probe_buffer` is placed in cache, because the CPU executed this command out of order.
- A Flush and reload can be used to identify the page offset of the cached page in probe buffer => 1 byte leaked.
- This can be repeated for any number of bytes: 

```
for (int i = 0; i < strlen(test); i++)
	{
		char byte = melt_byte_dynamic(test + i);
		printf("%c", byte);
	}
```

### Spectre

Follows the exact same logic but even simpler: 

- Instead of causing a page-fault/segfault and then checking the cache for cached pages, execute a function numerous times with the a condition being `TRUE` in it and use a *legal* address to index a probe buffer: 

```
// condition is always true
// target_address is actually legal. Nothing goes wrong
static void victim_function (size_t target_address)
{
	if (*condition) {
		char temp = probe_buffer[(*(volatile char *)_target_addr) * 4 * KB];	
	}
}
```

- After numerous times, suddenly: 
  - replace the `target_address ` with the illegal *target/kernel address* which is illegal to access.
  - set condition to `false`.

- execute function again. Now:
  - The condition is false so the memory access actually NEVER happens.
  - But, since the branch-predictor-unit of the cpu thinks that this condition is almost always true, it will still execute the memory access out-of-order

- Same cache side-channel attack (Flush+Reload) can be used to leak any number of arbitrary data bytes from any memory location. 

