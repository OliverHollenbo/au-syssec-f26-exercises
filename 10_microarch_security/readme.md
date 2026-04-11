# Exercises: Microarchitecture Security

Today we will take a deeper look into microarchitecture security exploits such as
FLUSH+RELOAD and Spectre, and how they target issues related to
cache-timing and speculative execution. As discussed in class, Spectre uses the FLUSH+RELOAD cache-timing side-channel attack to steal
sensitive data. 
This exercise is heavily
inspired by [SEED Labs](https://seedsecuritylabs.org/Labs_20.04/System/Spectre_Attack/).

## Exercise 1: Cache-based side-channel attacks

The CPU cache is a hardware component that reduces the
average cost to access data from the main memory, since accessing data from the cache
is much faster. When data is fetched from the main memory, it is usually stored in cache memory,
so it can be quickly found if the same data is used again (locality principle).
Hence, ache memory is used to hide the performance difference between the high-speed CPU and the slow main memory.

Let us see the time difference. In [cache-time.c](cache-time.c), we have an array of size `10*4096`.
We first access two of its elements, `array[3*4096]` and `array[7*4096]`. Therefore, the pages containing these two elements will be
cached. We then read the elements from `array[0*4096]` to `array[9*4096]` and measure the time
spent in the memory access. In the code, the CPU’s timestamp (TSC) counter is read before and after the memory reading.
Their difference is the time (in terms of number of CPU cycles) spent in the memory read. It should be noted that
caching is done at the memory block level, not at the byte level. A typical cache line size is 64 bytes. We use
`array[k*4096]`, so no two elements used in the program fall into the same cache line.

**Your task**: Compile the code using `gcc -march=native cache-time.c -o cache-time`, and run it. Is the
access of `array[3*4096]` and `array[7*4096]` faster than that of the other elements? You should
run the program at least 10 times and find a _threshold_ that can be used to distinguish these two types of memory access: accessing data from the cache (*hit*)
versus accessing data from the main memory (*cache hit*). This threshold is important for the rest of the tasks in this lab.

## Exercise 2: FLUSH+RELOAD

The objective of this task is to use the cache-based side channel to extract a secret value used by the victim function.
Assume there is a victim function that uses a secret value as index to load some values from an array.
The technique that we will be using is called FLUSH+RELOAD:

1. FLUSH the entire array from the cache memory to make sure the array is not cached.
2. Invoke the victim function, which accesses one of the array elements based on the value of the secret.
This action causes the corresponding array element to be cached.
3. RELOAD the entire array, and measure the time it takes to reload each element. If one specific
element’s loading time is fast, it is very likely that element is already in the cache. This element must
be the one accessed by the victim function. Therefore, we can figure out what the secret value is.

This vode in [flush-reload.c](flush-reload.c) uses this technique to find out a one-byte secret value contained in the variable `secret`.
Since there are 256 possible values for a one-byte secret, we need to map each value to an array element. The naive way is to define an array of 256 elements (i.e., `array[256]`).
However, this does not work: if `array[k]` is accessed, a block of memory containing this element will be cached. Therefore, the adjacent elements of `array[k]` will also be cached, making it difficult to infer what the secret is. To solve this problem, we create an array of `256*4096` bytes. Each element used in our RELOAD step is `array[k*4096]`. Because
`4096` is larger than a typical cache block size (64 bytes), no two different elements `array[i*4096]` and
`array[j*4096]` will be in the same cache line. We avoid using `array[0*4096]` because it may fall into the same cache block as the variables in the adjacent memory,
so we use `array[k*4096 + DELTA]` for all `k` values, where `DELTA` is defined as a constant `1024`.

**Your task**: Compile the code and run it for at least 20 times. Count how many times you will get the secret correctly.
You can also adjust the threshold to the one derived previously.

## Exercise 3: Out-of-order execution

CPU makers made a severe mistake in the design of the out-of-order execution. They
wipe out the effects of the out-of-order execution on registers and memory if such an execution is not
supposed to happen, so the execution does not lead to any visible effect. However, they forgot the effect on CPU caches. During the out-of-order execution, the referenced memory is fetched into a
register and is also stored in the cache, thus creating an observable effect.

In this task, we use an experiment to observe the effect caused by an out-of-order execution.
The code in [out-of-order.c](out-of-order.c) uses the FLUSH+RELOAD functions from before. As discussed in class, the Spectre exploit works as in the following:

1. Train the CPU to predict a branch to be taken in speculative execution
2. Once the CPU is trained, evict a variable from memory to start a transient window
3. Perform an invalid memory access within the transient window to force the CPU to speculatively read the value

**Your task**: Compile the code and run it to observe when line 58 is executed or not.
Please also comment line 55 and execute again, and think about what you observe.
After you are done with this experiment, uncomment it, so the subsequent tasks are not affected.

## Exercise 4: The Spectre Attack

As we have seen from the previous task, we can get CPUs to execute a true-branch of an if statement, even
though the condition is false, and traces will be left in the microarchicture.
The Spectre attack uses these traces to steal protected secrets, such as data in another process or data in the same process.
If the secret data is in another process, the process isolation at the hardware level prevents a process from stealing data from another
process. If the data is in the same process, the protection is usually done via software, such as sandbox
mechanisms. The Spectre attack can be launched against both types of secret. However, stealing data from
another process is much harder than stealing data from the same process. For the sake of simplicity, this lab
only focuses on stealing data from the same process.

In this task, there are two types of regions: restricted region and non-restricted. The restriction is achieved via a branch implemented in a sandbox
function described below. The sandbox function returns the value of `buffer[x]` for an `x` value provided
by users, only if `x` is between the buffer’s lower and upper bounds. Therefore, this sandbox function will
never return anything in the restricted area to users.

There is a secret value in the restricted area (either above the buffer or below it), and the secret’s address
is known to the attacker, but the attacker cannot directly access the memory holding the secret value. The
only way to access the secret is through the above sandbox function. From the previous section, we have
learned that although the true-branch will never be executed if x is larger than the buffer size, at microarchitectural level,
it can be executed and some traces can be left behind when the execution is reverted.

**Your task**: Please compile and execute [spectre.c](spectre.c), noting whether
you are able to steal the secret value. If there is a lot of noise in the side channel, you may not get consistent
results every time. To overcome this, you should execute the program multiple times and see whether you
can get the secret value.

## BONUS: Improve the accuracy

In the previous tasks, one can observe that the results do have some noise and the results are not always
accurate. This is because the CPU sometimes load extra values in cache expecting that it might be used at some
later point, or the threshold is not very accurate. This noise in cache can affect the results of our attack. We
need to perform the attack multiple times; instead of doing it manually, we can use the following code to
perform the task automatically.

We basically use a statistical technique. The idea is to create a `score` array of size 256, one element for
each possible secret value. We then run our attack multiple times. Each time, if our attack program says
that `k` is the secret (this result may be false), we add `1` to `scores[k]`. After running the attack for many
times, we use the value `k` with the highest score as our final estimation of the secret. This will produce a
much reliable estimation than the one based on a single run.

**Your task**: Revise the code using this idea and run it. You should revise the `reloadSideChannel()` function to take
the `scores` in consideration, and adapt the `main` function to repeat the attack 1000 times.
You may observe that when running the revised code, the position with the highest score is very likely to be `scores[0]`.
Please figure out why, and fix the code so the actual secret value will be printed out. The sleep time also affects the success rate of the attack.
Please try several other values, and see how they affect the accuracy.
Finally, extend the code to print out the entire string using the Spectre attack.

