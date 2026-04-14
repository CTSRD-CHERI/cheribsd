#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "scan_stash_ace_user_IO.h"

void usage(char *argv0, int exit_code)
{
  printf("Usage: %s ACTION\n", argv0);
  printf("ACTION must be one of:\n");
  printf(" --help          This usage.\n");
  printf(" --ace-enable    Turn on the ACE behavior in scan_stash_ace mod.\n");
  printf(" --ace-disable   Turn off the ACE behavior in scan_stash_ace mod.\n");

  exit(exit_code);
}

int main(int argc, char *argv[])
{
  int fd, ret;
  int request;

  if (argc != 2) {
    usage(argv[0], EXIT_FAILURE);
  }

  if (strcmp(argv[1], "--help") == 0 ||
      strcmp(argv[1], "-h") == 0)
  {
    usage(argv[0], EXIT_SUCCESS);
  } else if (strcmp(argv[1], "--ace-enable") == 0) {
    request = SIFT_SCAN_AND_STASH_IOC_ACE_ENABLE;
  } else if (strcmp(argv[1], "--ace-disable") == 0) {
    request = SIFT_SCAN_AND_STASH_IOC_ACE_DISABLE;
  } else {
    printf("Unknown command line argument: %s\n", argv[1]);
    exit(EXIT_FAILURE);
  }

  fd = open("/dev/scan_stash_ace_ctrl", O_RDONLY);
  if (fd < 0) {
    perror("open");
    exit(EXIT_FAILURE);
  }

  // Set attack bit to determine behavior of sas_ace.
  ret = ioctl(fd, request);
  if (ret < 0) {
    perror("ioctl");
    exit(EXIT_FAILURE);
  }

  switch(request) {
    case SIFT_SCAN_AND_STASH_IOC_ACE_ENABLE:
      printf("scan_stash ACE enabled.\n");
      break;
    case SIFT_SCAN_AND_STASH_IOC_ACE_DISABLE:
      printf("scan_stash ACE disabled.\n");
      break;
    default:
      printf("What? Unknown request!\n");
      exit(EXIT_FAILURE);
      break;
  }

  close(fd);

  return EXIT_SUCCESS;
}
