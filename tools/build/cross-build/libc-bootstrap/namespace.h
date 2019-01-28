#pragma once

#define _open(...)	open(__VA_ARGS__)
#define _close(a)	close(a)
#define _fstat(a, b)	fstat(a, b)
#define _read(a, b, c)	read(a, b, c)
#define _write(a, b, c)	write(a, b, c)
#define _writev(a, b, c)	writev(a, b, c)
#define _fsync(a)	fsync(a)
#define	_getprogname()	getprogname()
#define	_err(...)	err(__VA_ARGS__)

#define _pthread_mutex_unlock	pthread_mutex_unlock
#define _pthread_mutex_lock	pthread_mutex_lock

