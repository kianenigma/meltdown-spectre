# Meltdown and Spectre attacks

This repository provides a proof of concept implementation of the famous [Meltdown/Spectre](https://meltdownattack.com/) attacks, first found in January 2018. This repository is created based on the knowledge I gained during the great _Hardware Security_ course at the VU Amsterdam, coordinated by the renowned [VUSec team](https://www.vusec.net/). 

Spectre and Meltdown vulnerabilities share some, but not all characteristics and were both disclosed to public almost at the same time in the beginning of 2018. By far, these vulnerabilities [have](https://www.theinquirer.net/inquirer/news/3061135/intels-chips-are-riddled-with-more-speculative-execution-vulnerabilities) [gained](https://support.microsoft.com/en-us/help/4073757/protect-your-windows-devices-against-spectre-meltdown) [much](https://arstechnica.com/gadgets/2018/11/spectre-meltdown-researchers-unveil-7-more-speculative-execution-attacks/) [more](http://blog.cyberus-technology.de/posts/2018-01-03-meltdown.html) [exposure](https://www.crn.com/spectre-meltdown) and news coverage than any other recent event in the world of hardware security. It is plausibly deemed that these two are just beginning of a new class of vulnerabilities and exploits, which are predicted to be discovered in the upcoming years. This makes the understanding of the basis of these exploits crucial for any computer scientist/engineer. Having a brief look at the recent publications, we can already see that numerous variants and applications of these vulnerabilities are already being exploited, some of which being: 

- Foreshadow: Attacking Intel's --deemed-- super secure SGX technology with meltdown. 
- [Speculative Buffer Bypass](https://www.wired.com/story/speculative-store-bypass-spectre-meltdown-vulnerability/) (Variant 4 of Spectre and Meltdown)

> The rest fo this document is written in the simplest possible form. The intention is for it to be a guide for someone new to the field of security to be able to understand the vulnerabilities. 

### Table Of Content.

- Prerequisites
  - Optimization Fetish: Speculative/Out-Of-Order execution: _The basis of both attacks is built on top of this optimization, currently used in almost all major CPUs created by Intel and some AMD processors_.
  - Timing Side channels - Flush/Reload: _This simple approach will be used as the final step of the attack to leak the actual data_.
- Meltdown exploit
- Spectre exploit
- References+Links

# Prerequisites

## Optimization Fetish

The major flaw in both attacks, as you might have already guessed, is actually *not a flaw itself*. It is chip designer's response to to the user's (us!) ever-increasing demand for higher and higher performance. This is why CPU vendors have been applying and mastering the art of designing chips that execute instructions speculatively, in an optimized manner. This feature basically enables CPUs to not wait for slow instructions to finish and execute some other independent instructions in the meantime. Most of the times, such optimizations can be very effective to compensate for the slow access time of DRAMs; Namely when a read from memory (super-slow) is blocking computation instruction (super-fast).  

Two groups of such optimization are of our interest, namely **out-of-order** execution and **speculative** execution. Let's briefly have a look at what each of them is doing. 

#### Out-Of-Order Execution

Out of order execution is built around one core principle: CPU Pipelines. Pipelines enable CPUs to execute different stages of instruction in parallel. In the simplest form, this can be _fetch_, _decode_ and _execute_. Now, the purpose of out-of-order execution is that when one execution flow in the pipeline is blocked, the other flows (pipes) will not be blocked. In essense, from a programmers perspective, this can be translated to the following: 

```
char a = slow_read_from_mem();
int b = fast_computation();
```

When the CPU observes the above code, it has to wait a considerable amount of time for the first instruction to finish. To compensate, what it will do is to execute the second instruction **out-of-order**. But, it will **NOT** make its effects visible in the architectural level. 

> By architectural level, I mean everything that is directly visible to the programmer. Examples: variables, registers etc.

But, here's the trick: If the CPU decides that what it had executed out-of-order was a wrong instruction, it will NOT make the effort to clean the micro-architectural effects. 

> By architectural level, I mean everything that is NOT directly visible to the programmer. The most important example is the CPU cache. 

The major flaw stems from this observation: We can trick the CPU to execute an illegal instruction in an out-of-order manner and then try and leak information from the CPU cache.

#### Speculative Execution 

Speculative execution follows a very similar pattern: Executing an instruction in an optimized manner and then leaking from the micro-architectural state of the system. 

The main difference is that in this category we will focus on CPU units that will **speculate**. The best example of such is the _Branch-Predictor-Unit_. 

```
if (condition) {
  char a = read_from_mem(address);
}
```

in the above snippet, if the `condition` variable is almost always evaluated to `true`, then the BPU will speculate that this condition is *always* true. Now, if `condition` is suddenly `false`, it is very likely that the CPU will still speculate that it is `true`, and execute the instruction, until it finally realizes that it was wrong and revert the architectural state. This becomes crucially important when `condition` is somehow memory related and and slow to evaluate. 

This flow enables us to reach the same outcome as the previous: Trick the CPU to execute an invalid instruction speculatively and leak information.

## Timing Side channels - Flush/Reload

We have always mentioned that leaking information in the micro-architectural state (e.g. cache state) is enough. In this section, we will see how we can leak actual information from the altered cache state.

Flush+Reload is one of the most famous timing side-channel attacks, in which the access time to the memory is evaluated to infer if it was cached or not. We will go through a full example of this in the next section. Not quite realistic, but this assumption makes understanding of Flush+Reload easier: assume there is a common shared array between the attacker and the vitim process. Furthermore, assume that we know when the victim might have examined an element from this array. Now, the goal is to leak which index of the array was accessed. To do so, we do the following: 

- Flush the entire array from the cache. A naive way is to use `_clflush()`. A more realistic way is to create an *eviction set*.
- Wait for the victim to access an element from the array. 
- Examine the access time of all array element. Ideally, only one of the will be accessed with a significantly less time, hence, being cached. This leaks which index of the array was accessed by the victim using only micro-architectural information.

In the next section, we will see how this can be adapted to the Meltdown attack.

# Meltdown

We will begin the explanation by going through _Meltdown_, as I find it more intuitively understandable. Consequently, Spectre will follow a very similar pattern.

Recalling from the previous section, we set our attack plan as follows: 

- Trigger an illegal access, but make sure that the CPU *will execute it out-of-order*. 
- Recover from any fault that might happen.
- Examine the cache state and leak information.

Translating this to a code, we do the following:

We create an array called _probe buffer_. We use this array to index it via the value of the illegal target address.

```
#define PROBE_SIZE (1024 * 4 * 256)
char *probe_buffer = malloc(PROBE_SIZE);
```

We use `256` because each value in th target address to leak is at most one byte => 256 possible values. Furthermore, we use a stride of 4KB. This makes the eviction from the cache easier.

The rest of the attack can be summarized in one line: 

```
char temp = probe_buffer[(*(volatile char *)_target_addr) *4 * KB];
```

Let's walk you step by step through what will happen when this line is executed: 

1. The CPU starts by fetching the value at `_target_addr` variable (note the dereference `*`).
2. Since it takes some time for the machine to check if this address is allowed or not, CPU will continue executing the statement in an out of order manner. 
3. Hence, one of the elements of the `probe_array`, indexed but `*_target_addr`, strided by `4KB`, is eventually fetched from memory and placed in some arbitrary register, and placed in cache.
4. As soon as the CPU realizes that the access was NOT legal, all register values associated with this read are reverted, and a `segfault` signal is triggered.
5. Note that at this point we must recover from the `segfault`. We omit this part as it is not related to the attack. see the `setjmp()` call.
6. Finally, we trigger a Flush+Reload as the state of the cache is not altered and can easily see which 4KB offset of the `probe_buffer` was just accessed. This index is the value stored at `target_addr` pointer. Finally, 1 byte of information leaked via Meltdown!

Some notes: 

- Usually, to cancel noise, we leak each byte numerous times and then examine the values.
- The Flush+Reload explained in section 6 above is slightly different from what was mentioned earlier. Essentially, they are the same concept applied via two different ways. 

# Spectre

Spectre follows almost the exact same pattern as meltdown with just one exception: we do not have to recover from segfault. In fact, Spectre is actually magnificently ironic in the sense that we leak information from any address in virtual memory without ever reading it directly! We already mentioned that Spectre is based on speculative execution. Now, assume the following code: 

```
static void victim_function (size_t target_address)
{
	if (*condition) {
		*(probe_buffer + (*(volatile char *)target_address) * KB4);
	}
}
```

Assume we first call `victim_function` a few tens of times with `*condition = true` and `target_address` being an arbitrary, but **legal** address (some local pointer in the code). Then, we call `victim_function` with `*condition = false` and `target_address` being the illegal that we seek to leak. Let's see what happens: 

- In the first few executions of the `victim_function`, the internal condition is always true. Hence, the *BPU (branch predictor unit)* will learn/guess that it is *always true*.
- All reads so far are legal and arbitrary. 
- Suddenly, we set the `*condition` to false and the target address to an illegal address. 
- Now, our program will not run into any issues, since due to the `if (*condition)` the read will never happen. 
- But! the CPU will speculate that since the condition has always been true, it will be true again and will not for `*condition` to be evaluated and will execute the next line anyhow. 
- Now, we end up at the exact same configuration as if in Meltdown. We do NOT yet know what the leaked data is, but we know it is in cache, because the CPU was fooled to actually fetch it.

# References+Links

An earlier draft of this small documentation is available in the [meltdown-spectre.md](/meltdown-spectre) file. Other resources: 

- TODO