#include <stdint.h>
#include <stdio.h>

#include "petitmac.c"

// Getrandom
# if __GLIBC__ > 2 || __GLIBC_MINOR__ > 24

#include <sys/random.h>

#else /* older glibc */

#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

int getrandom(void *buf, size_t buflen, unsigned int flags) {
    return syscall(SYS_getrandom, buf, buflen, flags);
}
# endif

#ifndef MSIZE
#define MSIZE 1*1024
#endif

void setrandom(void* buf, size_t buflen) {
  size_t l = getrandom(buf, buflen, 0);
  if (l != buflen) {
    fprintf(stderr, "Error initializing random state\n");
    exit(EXIT_FAILURE);
  }
}

// Uncomment to use perf_event_open for benchmarks
// #define PERF_EV


// Uncomment to use rdpmc for benchmarks -- this requires running with perf stat -e cycles:u
// #define USE_RDPMC


#ifdef PERF_EV
// Sample code from perf_event_open manpage

#include <linux/perf_event.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                int cpu, int group_fd, unsigned long flags)
{
  int ret;
  
  ret = syscall(SYS_perf_event_open, hw_event, pid, cpu,
                group_fd, flags);
  return ret;
}
#endif

int main() {
  uint8_t *M  = calloc(MSIZE,1);
  uint8_t  N[16];
  uint8_t  K[16];
  uint8_t  T[16];

#ifdef PERF_EV
  int                     fd;
  long long               count;
  struct perf_event_attr  pe;
  
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_HARDWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_HW_CPU_CYCLES;
  pe.disabled = 1;
  pe.exclude_kernel = 1;
  pe.exclude_hv = 1;
  
  fd = perf_event_open(&pe, 0, -1, -1, 0);
  if (fd == -1) {
    fprintf(stderr, "Error opening leader %llx\n", pe.config);
    exit(EXIT_FAILURE);
  }
#endif

  setrandom(M, MSIZE);
  setrandom(N, sizeof(N));
  setrandom(K, sizeof(K));
  
  context ctx;
  petitmac_init(&ctx, K);

  // Blank computation
  petitmac_MAC(&ctx, N, M, MSIZE, T);

  // Benchmarks
  int cycles[1000];
  uint8_t Z = 0;
  for (int i=0; i<1000; i++) {
    getrandom(N, sizeof(N), 0);
#ifdef PERF_EV
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
#else
#ifdef USE_RDPMC
    unsigned long long start = __builtin_ia32_rdpmc(0);
    _mm_lfence();
#else
    uint32_t tmp;
    unsigned long long start = __builtin_ia32_rdtscp (&tmp);
#endif
#endif
    petitmac_MAC(&ctx, N, M, MSIZE, T);
    Z ^= T[0];
#ifdef PERF_EV
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    read(fd, &count, sizeof(count));
    cycles[i] = count;
#else
#ifdef USE_RDPMC
    _mm_lfence();
    unsigned long long stop = __builtin_ia32_rdpmc(0);
#else
    unsigned long long stop = __builtin_ia32_rdtscp (&tmp);
#endif
    cycles[i] = stop-start;
#endif
  }

  for (int i=0; i<1000; i++) {
    printf ("%5.3f\n", 1.0*cycles[i]/(MSIZE));
  }
  return Z; // Just force GCC to keep the computation
}
