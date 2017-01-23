/**
 * Check where the stack ends up to see if libprocstat is giving the correct reading.
 */

/* #include <sys/types.h> */
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{

  /* get stack pointer */
  uint64_t stack;
  uint64_t cap_stack;

  asm("move %0, $sp"
      : "=r" (stack));
  asm("ctoptr $at, $c11, $c0\n\t"
      "move %0, $at"
      : "=r" (cap_stack)
      :: "at");

  printf("Current pid %lu\n", getpid());
  printf("Stack pointer: 0x%0.16" PRIx64 "\n", stack);
  printf("Capability stack pointer: 0x%0.16" PRIx64 "\n", cap_stack);

  return 0;
}
