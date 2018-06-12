.\" NOTE:  changes to the manual page for "top" should be made in the
.\"        file "top.X" and NOT in the file "top.1".
.\" $FreeBSD$
.nr N %topn%
.nr D %delay%
.TH TOP 1 Local
.UC 4
.SH NAME
top \- display and update information about the top cpu processes
.SH SYNOPSIS
.B top
[
.B \-abCHIijnPqStuvwz
] [
.BI \-d count
] [
.BI \-m io | cpu
] [
.BI \-o field
] [
.BI \-s time
] [
.BI \-J jail
] [
.BI \-U username
] [
.I number
]
.SH DESCRIPTION
.\" This defines appropriate quote strings for nroff and troff
.ds lq \&"
.ds rq \&"
.if t .ds lq ``
.if t .ds rq ''
.\" Just in case these number registers aren't set yet...
.if \nN==0 .nr N 10
.if \nD==0 .nr D 2
.I Top
displays the top
.if !\nN==-1 \nN
processes on the system and periodically updates this information.
.if \nN==-1 \
\{\
If standard output is an intelligent terminal (see below) then
as many processes as will fit on the terminal screen are displayed
by default.  Otherwise, a good number of them are shown (around 20).
.\}
Raw cpu percentage is used to rank the processes.  If
.I number
is given, then the top
.I number
processes will be displayed instead of the default.
.PP
.I Top
makes a distinction between terminals that support advanced capabilities
and those that do not.  This
distinction affects the choice of defaults for certain options.  In the
remainder of this document, an \*(lqintelligent\*(rq terminal is one that
supports cursor addressing, clear screen, and clear to end of line.
Conversely, a \*(lqdumb\*(rq terminal is one that does not support such
features.  If the output of
.I top
is redirected to a file, it acts as if it were being run on a dumb
terminal.
.SH OPTIONS
.TP
.B \-C
Toggle CPU display mode.
By default top displays the weighted CPU percentage in the WCPU column
(this is the same value that
.IR ps (1)
displays as CPU).
Each time
.B \-C
flag is passed it toggles between \*(lqraw cpu\*(rq mode
and \*(lqweighted cpu\*(rq mode, showing the \*(lqCPU\*(rq or
the \*(lqWCPU\*(rq column respectively.
.TP
.B \-S
Show system processes in the display.  Normally, system processes such as
the pager and the swapper are not shown.  This option makes them visible.
.TP
.B \-a
Display command names derived from the argv[] vector, rather than real
executable name. It's useful when you want to watch applications, that
puts their status information there. If the real name differs from argv[0],
it will be displayed in parenthesis.
.TP
.B \-b
Use \*(lqbatch\*(rq mode.  In this mode, all input from the terminal is
ignored.  Interrupt characters (such as ^C and ^\e) still have an effect.
This is the default on a dumb terminal, or when the output is not a terminal.
.TP
.B \-H
Display each thread for a multithreaded process individually.
By default a single summary line is displayed for each process.
.TP
.B \-i
Use \*(lqinteractive\*(rq mode.  In this mode, any input is immediately
read for processing.  See the section on \*(lqInteractive Mode\*(rq
for an explanation of
which keys perform what functions.  After the command is processed, the
screen will immediately be updated, even if the command was not
understood.  This mode is the default when standard output is an
intelligent terminal.
.TP
.B \-I
Do not display idle processes.
By default, top displays both active and idle processes.
.TP
.B \-j
Display the
.IR jail (8)
ID.
.TP
.B \-t
Do not display the
.I top
process.
.TP
.BI \-m display
Display either 'cpu' or 'io' statistics.  Default is 'cpu'.
.TP
.B \-n
Use \*(lqnon-interactive\*(rq mode.  This is identical to \*(lqbatch\*(rq
mode.
.TP
.B \-P
Display per-cpu CPU usage statistics.
.TP
.B \-q
Renice
.I top
to -20 so that it will run faster.  This can be used when the system is
being very sluggish to improve the possibility of discovering the problem.
This option can only be used by root.
.TP
.B \-u
Do not take the time to map uid numbers to usernames.  Normally,
.I top
will read as much of the file \*(lq/etc/passwd\*(rq as is necessary to map
all the user id numbers it encounters into login names.  This option
disables all that, while possibly decreasing execution time.  The uid
numbers are displayed instead of the names.
.TP
.B \-v
Write version number information to stderr then exit immediately.
No other processing takes place when this option is used.  To see current
revision information while top is running, use the help command \*(lq?\*(rq.
.TP
.B \-w
Display approximate swap usage for each process.
.TP
.B \-z
Do not display the system idle process.
.TP
.BI \-d count
Show only
.I count
displays, then exit.  A display is considered to be one update of the
screen.  This option allows the user to select the number of displays he
wants to see before
.I top
automatically exits.  For intelligent terminals, no upper limit
is set.  The default is 1 for dumb terminals.
.TP
.BI \-s time
Set the delay between screen updates to
.I time
seconds.  The default delay between updates is \nD seconds.
.TP
.BI \-o field
Sort the process display area on the specified field.  The field name
is the name of the column as seen in the output, but in lower case:
\*(lqcpu\*(lq, \*(rqsize\*(lq, \*(rqres\*(lq, \*(rqtime\*(lq,
\*(rqpri\*(lq, \*(rqthreads\*(lq, \*(lqtotal\*(lq, \*(rqread\*(lq,
\*(rqwrite\*(lq, \*(rqfault\*(lq, \*(rqvcsw\*(lq, \*(rqivcsw\*(lq,
\*(lqjid\*(lq, \*(rqswap\*(lq or \*(rqpid\*(lq.
.TP
.BI \-J jail
Show only those processes owned by
.IR jail .
This may be either the
.B jid
or
.B name
of the jail.
Use
.B 0
to limit to host processes.
Using this option implies the
.B \-j
flag.
.PP
.BI \-U username
Show only those processes owned by
.IR username .
This option currently only accepts usernames and will not understand
uid numbers.
.PP
Both
.I count
and
.I number
fields can be specified as \*(lqinfinite\*(rq, indicating that they can
stretch as far as possible.  This is accomplished by using any proper
prefix of the keywords
\*(lqinfinity\*(rq,
\*(lqmaximum\*(rq,
or
\*(lqall\*(rq.
The default for
.I count
on an intelligent terminal is, in fact,
.BI infinity .
.PP
The environment variable
.B TOP
is examined for options before the command line is scanned.  This enables
a user to set his or her own defaults.  The number of processes to display
can also be specified in the environment variable
.BR TOP .
The options
.BR \-a ,
.BR \-C ,
.BR \-H ,
.BR \-I ,
.BR \-j ,
.BR \-P ,
.BR \-S ,
.BR \-t ,
.BR \-u ,
.BR \-w ,
and
.B \-z
are actually toggles.  A second specification of any of these options
will negate the first.  Thus a user who has the environment variable
.B TOP
set to \*(lq\-I\*(rq may use the command \*(lqtop \-I\*(rq to see idle processes.
.SH "INTERACTIVE MODE"
When
.I top
is running in \*(lqinteractive mode\*(rq, it reads commands from the
terminal and acts upon them accordingly.  In this mode, the terminal is
put in \*(lqCBREAK\*(rq, so that a character will be
processed as soon as it is typed.  Almost always, a key will be
pressed when
.I top
is between displays; that is, while it is waiting for
.I time
seconds to elapse.  If this is the case, the command will be
processed and the display will be updated immediately thereafter
(reflecting any changes that the command may have specified).  This
happens even if the command was incorrect.  If a key is pressed while 
.I top
is in the middle of updating the display, it will finish the update and
then process the command.  Some commands require additional information,
and the user will be prompted accordingly.  While typing this information
in, the user's erase and kill keys (as set up by the command
.IR stty )
are recognized, and a newline terminates the input.
.PP
These commands are currently recognized (^L refers to control-L):
.TP
.B ^L
Redraw the screen.
.IP "\fBh\fP\ or\ \fB?\fP"
Display a summary of the commands (help screen).  Version information
is included in this display.
.TP
.B q
Quit
.IR top.
.TP
.B d
Change the number of displays to show (prompt for new number).
Remember that the next display counts as one, so typing
.B d1
will make
.I top
show one final display and then immediately exit.
.TP
.B m
Toggle the display between 'cpu' and 'io' modes.
.TP
.B n or #
Change the number of processes to display (prompt for new number).
.TP
.B s
Change the number of seconds to delay between displays
(prompt for new number).
.TP
.B S
Toggle the display of system processes.
.TP
.B a
Toggle the display of process titles.
.TP
.B k
Send a signal (\*(lqkill\*(rq by default) to a list of processes.  This
acts similarly to the command
.IR kill (1)).
.TP
.B r
Change the priority (the \*(lqnice\*(rq) of a list of processes.
This acts similarly to the command
.IR renice (8)).
.TP
.B u
Display only processes owned by a specific set of usernames (prompt for
username).  If the username specified is simply \*(lq+\*(rq or \*(lq-\*(rq,
then processes belonging to all users will be displayed. Usernames can be added
to and removed from the set by prepending them with \*(lq+\*(rq and
\*(lq-\*(rq, respectively.
.TP
.B o
Change the order in which the display is sorted.  This command is not
available on all systems.  The sort key names vary from system to system
but usually include:  \*(lqcpu\*(rq, \*(lqres\*(rq, \*(lqsize\*(rq,
\*(lqtime\*(rq.  The default is cpu.
.TP
.B e
Display a list of system errors (if any) generated by the last
.BR k ill
or
.BR r enice
command.
.TP
.B H
Toggle the display of threads.
.TP
.B i
(or
.BR I )
Toggle the display of idle processes.
.TP
.B j
Toggle the display of
.IR jail (8)
ID.
.TP
.B J
Display only processes owned by a specific jail (prompt for jail).
If the jail specified is simply \*(lq+\*(rq, then processes belonging
to all jails and the host will be displayed.
This will also enable the display of JID.
.TP
.B P
Toggle the display of per-CPU statistics.
.TP
.B t
Toggle the display of the
.I top
process.
.TP
.B w
Toggle the display of swap usage.
.TP
.B z
Toggle the display of the system idle process.
.SH "THE DISPLAY"
The actual display varies depending on the specific variant of Unix
that the machine is running.  This description may not exactly match
what is seen by top running on this particular machine.  Differences
are listed at the end of this manual entry.
.PP
The top few lines of the display show general information
about the state of the system, including
the last process id assigned to a process (on most systems),
the three load averages,
the current time,
the number of existing processes,
the number of processes in each state
(sleeping, running, starting, zombies, and stopped),
and a percentage of time spent in each of the processor states
(user, nice, system, and idle).
It also includes information about physical and virtual memory allocation.
.PP
The remainder of the screen displays information about individual
processes.  This display is similar in spirit to
.IR ps (1)
but it is not exactly the same.  PID is the process id, 
JID, when displayed, is the 
.IR jail (8)
ID corresponding to the process,
USERNAME is the name of the process's owner (if
.B \-u
is specified, a UID column will be substituted for USERNAME),
PRI is the current priority of the process,
NICE is the nice amount (in the range \-20 to 20),
SIZE is the total size of the process (text, data, and stack),
RES is the current amount of resident memory,
SWAP is the approximate amount of swap, if enabled
(SIZE, RES and SWAP are given in kilobytes),
STATE is the current state (one of \*(lqSTART\*(rq, \*(lqRUN\*(rq
(shown as \*(lqCPUn\*(rq on SMP systems), \*(lqSLEEP\*(rq, \*(lqSTOP\*(rq,
\*(lqZOMB\*(rq, \*(lqWAIT\*(rq, \*(lqLOCK\*(rq or the event on which the
process waits),
C is the processor number on which the process is executing
(visible only on SMP systems),
TIME is the number of system and user cpu seconds that the process has used,
WCPU, when displayed, is the weighted cpu percentage (this is the same
value that
.IR ps (1)
displays as CPU),
CPU is the raw percentage and is the field that is sorted to determine
the order of the processes, and
COMMAND is the name of the command that the process is currently running
(if the process is swapped out, this column is marked \*(lq<swapped>\*(rq).
.SH NOTES
If a process is in the \*(lqSLEEP\*(rq or \*(lqLOCK\*(rq state,
the state column will report the name of the event or lock on which the
process is waiting.
Lock names are prefixed with an asterisk \*(lq*\*(rq while sleep events
are not.
.SH AUTHOR
William LeFebvre, EECS Department, Northwestern University
.SH ENVIRONMENT
.DT
TOP	user-configurable defaults for options.
.SH FILES
.DT
/dev/kmem		kernel memory
.br
/dev/mem		physical memory
.br
/etc/passwd		used to map uid numbers to user names
.br
/boot/kernel/kernel	system image
.SH BUGS
Don't shoot me, but the default for
.B \-I
has changed once again.  So many people were confused by the fact that
.I top
wasn't showing them all the processes that I have decided to make the
default behavior show idle processes, just like it did in version 2.
But to appease folks who can't stand that behavior, I have added the
ability to set \*(lqdefault\*(rq options in the environment variable
.B TOP
(see the OPTIONS section).  Those who want the behavior that version
3.0 had need only set the environment variable
.B TOP
to \*(lq\-I\*(rq.
.PP
The command name for swapped processes should be tracked down, but this
would make the program run slower.
.PP
As with
.IR ps (1),
things can change while
.I top
is collecting information for an update.  The picture it gives is only a
close approximation to reality.
.SH "SEE ALSO"
kill(1),
ps(1),
stty(1),
mem(4),
renice(8)
