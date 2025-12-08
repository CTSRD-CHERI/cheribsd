This module implements the ace2 syncpoint KPI, file interface, and kernel
output interface:

- Kernel components may call ace2_syncpoint() and ace2_observe() as in the
  original SIFT module design for Linux.

- The ace2_syncpoint module will generate kernel console output trackable via
  /dev/messages and similar, based on the Linux output.  This may require
  further adaptation.

- Unlike in Linux, the files appear in /dev/ace2_syncpoint, as procfs is not
  mounted by default in BSD, and also serves a somewhat different function.

In addition, there are several sysctls available to manage its functionality:

dev.ace2.syncpoint.list

  Read with 'sysctl -b' to see a list of current active syncpoints with
  various flags, stats, and fields.

dev.ace2.syncpoint.count 

  Number of active syncpoints currently.

dev.ace2.syncpoint.nextid

  Number of the next syncpoint ID that will be allocated.

dev.ace2.syncpoint.enabled

  Whether syncpoints are enabled; can be set to '1' (default) or '0'.

dev.ace2.syncpoint.test.example2
dev.ace2.syncpoint.test.example1

  Two test syncpoints included in the module.
