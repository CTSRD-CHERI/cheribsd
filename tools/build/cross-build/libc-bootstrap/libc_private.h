#pragma once

#define __libc_sigprocmask(a, b, c) sigprocmask(a, b, c)
