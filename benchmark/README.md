Benchmarking code
-----------------

This folder contains a optimized implementations of LeMac and PetitMac
as well as some other MACs from the literature, and benchmarking code
to compare their performance on x86 CPUs with AES-NI.

## Running the benchmarks

Just run the `benchmarks` script in the `benchmark` folder.
It will compile and run the benchmarks for all available MACs.

This scipt is written for Linux, and requires a C compiler, the `make`
program, and the `perf` program (for measurements using `RDPMC`).

The script uses `sudo` to obtain root access to set-up a better
benchmarking environment:
- disabling turbo boost
- disabling frequency scaling
- enabling performance measurement with `perf` and `RDPMC`

It tries to revert the machine to the initial state at the end, but this
is not guaranteed to succeed.

If you do not have root access (or do not want to grant root access to
the script), you can disable root access at the top of the script or run
it with `NO_ROOT=1 ./benchmarks`


## Benchmark results

The `benchmarks` script report performance in cycle per byte for
available MACs for several message lengths.  For more details and
potential error messages, check the `benchmarks.log` file.

The `benchmarks` scripts compiles and runs the `bench` program in each
cipher folder.  For each cipher, the script run benchmarks with three
different message sizes: 1kB, 16kB and 256kB.  The `bench` program
measure the speed of the MAC by running it 1000 times over the same
random message in memory.

The `benchmarks` scripts counts the frequency of each results, and sorts
them.  In the log file you can see the full range of results, while the
script output just reports the most commun value over 1000 runs.


## Configuring the benchmarks

The benchmarking code can use three different intructions to measure
speed.  You can select one option by editing the `benchmarks` script.
By default it will use `RDPMC` (or `RDTSC` if run with `NO_ROOT`).


1. `RDPMC` instruction

This is usually the most accurate.  However, this requires setting up
the perf counters, which often requires superuser access (the script
will try to enable the required permissions).

2. `perf_event_open` interface

This is sometimes available to non-root users, but it is less precise than
using RDPMC directly.

3. `RDTSC` instruction

This does not require root access and is accurate on Intel CPU, but on
AMD CPU the frequency of the RDTSC counter does not match the frequency
of the CPU core.

## MACs Benchmarked

The following MACs are included for benchmarking:

- aegis128: implementation `aesni` from supercop
- aegis128l: implementation `aesnic` from supercop
- GCM: implementation `dolbeau/aesenc-int` from supercop, and 
- The Jean-Nikolić construction: implementation based on LeMac implementation
- Rocca: reference code from the ePrint paper: https://eprint.iacr.org/2022/116.pdf
- Rocca-S: reference code from the draft RFC: https://www.ietf.org/archive/id/draft-nakano-rocca-s-05.html
- Tiaoxin: implementation `aesnim` from supercop

Original supercop implementations can be obtained by downloading https://bench.cr.yp.to/supercop/supercop-20240909.tar.xz
