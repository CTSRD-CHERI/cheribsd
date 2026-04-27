#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <kvm.h>
#include <sys/sysctl.h>
#include <libprocstat.h>
#include <libutil.h>

#include "scan_stash_user_IO.h"
#include "scan_stash_user_secret.h"

static_assert(sizeof(struct secret) == 64, "struct secret size");
static_assert(alignof(struct secret) == 64, "struct secret align");

/*
 * This volatile qualifier may be unncessary, but it'll ensure that the
 * compiler initializes the secret before the ioctl runs even though
 * the ioctl call is never given the address of the secret.
*/
volatile struct secret secret; 

// error printing
int eprintf(const char *fmt, ...)
{
  int ret;
  int saved_errno = errno;

  va_list ap;
  va_start(ap, fmt);

  ret = vfprintf(stderr, fmt, ap);

  va_end(ap);
  errno = saved_errno;

  return ret;
}

void make_secret()
{
  eprintf("&secret = %p\n", &secret);
  memset((void *)&secret, 0, sizeof(struct secret));
  memcpy((void *)&secret.secret_top_str[0], "=== BEGIN SECRET ===", 20);

  // The secret is: "deadbeef-53c237-deadbeef"
  memcpy((void*)secret.secret_data.secret_u8s, "deadbeef-53c237-deadbeef", 24);

  memcpy((void *)&secret.secret_bot_str[0], "==== END SECRET ====", 20);
}

void print_all(int fd, size_t max_len)
{
  const size_t BUFSZ = 4096;
  char buf[BUFSZ];
  int ret;
  int flags;
  ssize_t read_len;
  ssize_t total_read = 0;

  flags = fcntl(fd, F_GETFL);
  eprintf("fcntl(%d, F_GETFL) = %x\n", fd, flags);
  if (flags == -1) {
    perror("fcntl F_GETFL");
    exit(EXIT_FAILURE);
  }

  ret = fcntl(fd, F_SETFL, flags, O_NONBLOCK);
  eprintf("fcntl(%d, F_SETFL, %x) = %x\n", fd, flags | O_NONBLOCK, ret);
  if (ret == -1) {
    perror("fcntl F_SETFL");
    exit(EXIT_FAILURE);
  }

  while (max_len) {
    read_len = read(fd, buf, BUFSZ);
    eprintf("read(%d, %p, %zd) = %zd\n", fd, buf, BUFSZ, read_len);
    if (read_len == 0) {
      break;
    }

    if (read_len == -1) {
      perror("read");
      exit(EXIT_FAILURE);
    }

    max_len -= read_len;
    total_read += read_len;
  }

  printf("Read %zd bytes from kernel (KeRNel DaTa) from pipe:\n", total_read);
  hexdump(buf, total_read, "KRNDT:", 0);
}

void dump_kinfo_vme(char *fname, struct kinfo_vmentry *vme, 
                    unsigned int num_vm_count)
{
  int i, kt;
  struct kinfo_vmentry *v;
  int fd;

  fd = creat(fname, S_IRUSR | S_IWUSR);
  
  dprintf(fd, "%3s %18s %18s %3s %3s %4s %3s %3s %-5s %2s %s\n",
     "SEG",
     "START",
     "END",
     "PRT",
     "RES",
     "PRES",
     "REF",
     "SHD",
     "FLAG",
     "TP",
     "PATH"
     );

  for (i = 0; i < num_vm_count; i++) {
    v = &vme[i];
    kt = v->kve_type;

    dprintf(fd, 
       "%3d 0x%016lx-0x%016lx %c%c%c %3d %4d %3d %3d %c%c%c%c%c %2s %s\n",
       i,
       v->kve_start,
       v->kve_end,
       v->kve_protection & KVME_PROT_READ ? 'r' : '-',
       v->kve_protection & KVME_PROT_WRITE ? 'w' : '-',
       v->kve_protection & KVME_PROT_EXEC ? 'x' : '-',
       v->kve_resident,
       v->kve_private_resident,
       v->kve_ref_count,
       v->kve_shadow_count,
       v->kve_flags & KVME_FLAG_COW ? 'C' : '-',
       v->kve_flags & KVME_FLAG_NEEDS_COPY ? 'N' : '-',
       v->kve_flags & KVME_FLAG_SUPER ? 'S' : '-',
       v->kve_flags & KVME_FLAG_GROWS_DOWN ? 'D' : '-',
       v->kve_flags & KVME_FLAG_USER_WIRED ? 'W' : '-',

       kt == KVME_TYPE_NONE ? "--" :
       kt == KVME_TYPE_DEFAULT ? "df" :
       kt == KVME_TYPE_VNODE ? "vn" :
       kt == KVME_TYPE_SWAP ? "sw" :
       kt == KVME_TYPE_DEVICE ? "dv" :
       kt == KVME_TYPE_PHYS ? "ph" :
       kt == KVME_TYPE_DEAD ? "dd" :
       kt == KVME_TYPE_SG ? "sg" :
       kt == KVME_TYPE_MGTDEVICE ? "md" :
       kt == KVME_TYPE_GUARD ? "gd" :
       kt == KVME_TYPE_UNKNOWN ? "??" :
       "??",

       v->kve_path
       );
  }

  fsync(fd);
  close(fd);
}

int dump_vme(char *fname)
{
  pid_t pid;
  struct kinfo_proc *kp;
  struct procstat *ps;
  unsigned int num_procs_count;
  unsigned int num_vm_count;
  struct kinfo_vmentry *vme;

  pid = getpid();
  printf("\nPid is %d\n", pid);

  printf("pagesize is: %ld\n", sysconf(_SC_PAGESIZE));

  ps = procstat_open_sysctl();
  printf("procstat struct: %p\n", ps);

  /* This returns a kinfo_proc array num_procs_count long */
  kp = procstat_getprocs(ps, KERN_PROC_PID, pid, &num_procs_count);
  printf("kinfo_proc struct: %p, num_procs_count: %u\n", kp, num_procs_count);

  /* This returns a kinfo_vmentry array num_vm_count long */
  vme = procstat_getvmmap(ps, kp, &num_vm_count);
  printf("kinfo_vmentry struct: %p, num_vm_count: %u\n", kp, num_vm_count);

  /* dump all segments */
  dump_kinfo_vme(fname, vme, num_vm_count);

  procstat_freevmmap(ps, vme);

  procstat_freeprocs(ps, kp);

  procstat_close(ps);

  return 0;
}

int main(int argc, char *argv[])
{
  int fd;
  int ret;
  int pipefd[2];

  if (argc != 2) {
    printf(
      "Please supply a filename into which the VM map is printed.\n"
      "The VM map is printed into that file such that a kernel panic\n"
      "has the least chance of preventing the map from being observable.\n"
    );
    exit(EXIT_FAILURE);
  }

  make_secret();

  fd = open("/dev/scan_stash", O_RDONLY);
  eprintf("open(\"/dev/scan_stash\", O_RDONLY) = %d\n", fd);
  if (fd == -1) {
    perror("open");
    exit(EXIT_FAILURE);
  }

  /*
   * Dump virtual memory info of current thread to out file, where
   * we can inspect which kinds of pages the kernel code skips during
   * its search through the address space.
   */
  dump_vme(argv[1]);

  // create pipe to write and read data found by the module
  ret = pipe(pipefd);
  eprintf("pipe([%d, %d]) = %d\n", pipefd[0], pipefd[1], ret);
  if (ret == -1) {
    perror("pipe");
    exit(EXIT_FAILURE);
  }
  
  // This is the ioctl where we the kernel searches through the
  // stack segment looking for something.
  ret = ioctl(fd, SIFT_SCAN_AND_STASH_IOC_SRCH, &pipefd[1]);
  eprintf("ioctl(%d, SIFT_SCAN_AND_STASH_IOC_SRCH, %d) = %d\n",
          fd, pipefd[1], ret);
  if (ret == -1) {
    perror("ioctl\n");
    exit(EXIT_FAILURE);
  }

  // Emit the information
  close(pipefd[1]);
  print_all(pipefd[0], 24);
  close(pipefd[0]);  

  close(fd);

  return 0;
}
