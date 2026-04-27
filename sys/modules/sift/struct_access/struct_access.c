#include <sys/types.h>
#include <sys/systm.h>  /* uprintf */
#include <sys/param.h>  /* defines used in kernel.h */
#include <sys/module.h>
#include <sys/kernel.h> /* types used in module initialization */
#include <sys/conf.h>   /* cdevsw struct */
#include <sys/uio.h>    /* uio struct */
#include <sys/malloc.h>
#include <sys/syslog.h>

#define BASE_DIR "struct-access"
#define PRIVATE (BASE_DIR "/" "private")
#define PUBLIC (BASE_DIR "/" "public")

#define PRIVATE_BUFFER_SIZE  1024
#define PUBLIC_BUFFER_SIZE  1024

// TODO: This is here for testing purposes. I have tested that the exploit
// works with SIFT_ACE enabled and doesn't with it disabled.
#define SIFT_ACE

struct sift_struct_access_ace_context
{
    int (*private_read_func)(struct cdev *dev __unused, struct uio *uio,
                                int ioflag __unused);
    struct uio **uio_addr;
    struct cdev **dev_addr;
    int *ioflag_addr;
    volatile bool checked;
    volatile bool triggered;
    volatile bool early_return;
    volatile int return_value;
};

void
sift_struct_access_ace(volatile struct sift_struct_access_ace_context *ctx);

#ifdef SIFT_ACE
void sift_struct_access_ace(volatile struct sift_struct_access_ace_context *ctx)
{
    int (*private_read_func)(struct cdev *dev __unused, struct uio *uio,
                                int ioflag __unused);
    struct uio *uio = NULL;
    struct cdev *dev = NULL;
    int ioflag;

    ctx->checked = true;

    private_read_func = ctx->private_read_func;
    uio = *ctx->uio_addr;
    dev = *ctx->dev_addr;
    ioflag = *ctx->ioflag_addr;

    printf("ACE Context at %p, checked[%s], triggered[%s]\n",
        ctx,
        ctx->checked ? "true" : "false",
        ctx->triggered ? "true" : "false"
    );

    if (uio->uio_offset > 0 &&
        (uio->uio_resid - PUBLIC_BUFFER_SIZE) == PRIVATE_BUFFER_SIZE)
    {
        int ret;
        off_t orig_offset;

        // We actually are doing the ACE right now!
        ctx->triggered = true;

        printf("struct-access: PUBR SIFT ACE triggered\n");
        orig_offset = uio->uio_offset;
        printf("struct-access: PUBR SIFT ACE original resid: %zu, off: %ld\n",
            uio->uio_resid, orig_offset);

        // Grab up to all data from start of private buffer.
        uio->uio_resid = PRIVATE_BUFFER_SIZE;
        uio->uio_offset = 0;

        // ACE calls the wrong function to do the work.
        ret = private_read_func(dev, uio, ioflag);

        printf("struct-access: PUBR SIFT ACE exploited resid: %zu, off: %ld\n",
            uio->uio_resid, orig_offset);

        // Then make it like read() read all the bytes in question, but never
        // moved the offset. Read should report that it read the exploit
        // number of bytes though only up to private_size is actually read.
        uio->uio_resid = 0;
        uio->uio_offset = orig_offset;

        // Fix up the ACE Context to specify an early return at call site.
        ctx->early_return = true;
        ctx->return_value = ret;
    }
}

#else

void sift_struct_access_ace(volatile struct sift_struct_access_ace_context *ctx)
{
    printf("ACE NOP Context at %p, checked[%s], triggered[%s]\n",
        ctx,
        ctx->checked ? "true" : "false",
        ctx->triggered ? "true" : "false"
    );
}
#endif

/* ------------------------------------------------------------------------- */
/* The buffers that we will corrupt. */
/* ------------------------------------------------------------------------- */

struct sift_struct_access {
    char public_buffer[PUBLIC_BUFFER_SIZE];
    char private_buffer[PRIVATE_BUFFER_SIZE];
    size_t public_size; /* amount initially written */
    size_t private_size; /* amount initially written. */
};

static struct sift_struct_access sift_struct_access_data;


/* ------------------------------------------------------------------------- */
/* PRIVATE file operations. */
/* ------------------------------------------------------------------------- */


static int
sift_private_struct_access_read(struct cdev *dev __unused, struct uio *uio,
                                 int ioflag __unused)
{
    int error = 0;
    ssize_t amt;

    log(LOG_INFO, "struct-access: PRIR "
            "sift_private_struct_access_read invoked\n");

    printf("struct-access: PRIR Private buffer contains:\n");
    if (sift_struct_access_data.private_size > 0) {
        hexdump(sift_struct_access_data.private_buffer,
                sift_struct_access_data.private_size,
                "PRIR: ", 0);
    } else {
        printf("struct-access: PRIR No buffer data.\n");
    }

    while (uio->uio_resid > 0 && error == 0) {
        printf("struct-access: PRIR Loop start: req %zu bytes at %ld\n",
            uio->uio_resid, uio->uio_offset);

        amt = uio->uio_offset > sift_struct_access_data.private_size
              ? 0
              : uio->uio_offset + uio->uio_resid >
                    sift_struct_access_data.private_size
                ? sift_struct_access_data.private_size - uio->uio_offset
                : uio->uio_resid;

        printf("struct-access: PRIR "
            "Determined amt to be %zu of %zu bytes at offset %ld\n",
            amt, uio->uio_resid, uio->uio_offset);

        if (amt == 0) {
            printf("struct-access: PRIR "
                    "Exit loop due to zero bytes available to be presented.\n");
            break;
        }

        printf("struct-access: PRIR "
                "Transfer clipped %zu bytes starting at %ld\n",
                amt, uio->uio_offset);

        // do the read
        error =
            uiomove(&sift_struct_access_data.private_buffer[uio->uio_offset],
                    amt, uio);

        printf("struct-access: PRIR "
               "Next read req will be: %zu bytes, offset %ld, error %d\n",
            uio->uio_resid, uio->uio_offset, error);
    }

    printf("struct-access: PRIR "
            "Done reading from kernel buffer: uio_resid=%zu, uio_offset=%ld, "
            "error=%d\n",
            uio->uio_resid, uio->uio_offset, error);

    return error;
}

static int
sift_private_struct_access_write(struct cdev *dev __unused, struct uio *uio,
                                    int ioflag __unused)
{
    int error = 0;
    ssize_t amt;
    ssize_t bytes_to_ignore = 0;

    while (uio->uio_resid > 0 && error == 0) {
        printf("struct-access: PRIW Loop start: req %zu bytes at %ld\n",
            uio->uio_resid, uio->uio_offset);

        // write up to, but not beyond, the real end of the buffer.
        amt = uio->uio_offset >= PRIVATE_BUFFER_SIZE
              ? 0
              : uio->uio_offset + uio->uio_resid >= PRIVATE_BUFFER_SIZE
                ? PRIVATE_BUFFER_SIZE - uio->uio_offset
                : uio->uio_resid;

        bytes_to_ignore = uio->uio_resid - amt;

        printf("struct-access: PRIW "
            "Determined amt to be %zu of %zu bytes at offset %ld\n",
            amt, uio->uio_resid, uio->uio_offset);

        if (amt == 0) {
            printf("struct-access: PRIW "
                    "Exit loop due to zero bytes available to be accepted.\n");
            break;
        }

        printf("struct-access: PRIW "
                "Transfer clipped %zu bytes starting at %ld\n",
                amt, uio->uio_offset);

        // do the write
        error =
            uiomove(&sift_struct_access_data.private_buffer[uio->uio_offset],
                amt, uio);

        printf("struct-access: PRIW "
               "Next write req will be: %zu bytes, offset %ld\n",
            uio->uio_resid, uio->uio_offset);
    }

    printf("struct-access: PRIW Done writing to kernel buffer.\n");

    // store the total size we ended up writing into the buffer.
    sift_struct_access_data.private_size = uio->uio_offset;

    // NOW we can "consume" all the remaining bytes we don't want.
    printf("struct-access: PRIW Draining remaining %zu bytes\n",
            bytes_to_ignore);
    uio->uio_offset += bytes_to_ignore;
    uio->uio_resid = 0;

    // debugging output
    printf("struct-access: PRIW Private buffer contains:\n");
    hexdump(sift_struct_access_data.private_buffer,
            sift_struct_access_data.private_size,
            "PRIW: ", 0);

    return error;
}

static struct cdevsw private_cdevsw = {
  .d_name         = PRIVATE,
  .d_version      = D_VERSION,
  .d_flags        = D_TRACKCLOSE,
  .d_read         = sift_private_struct_access_read,
  .d_write        = sift_private_struct_access_write,
};

/* filled in by make_dev_p */
static struct cdev *private_dev;


/* ------------------------------------------------------------------------- */
/* PUBLIC file operations. */
/* ------------------------------------------------------------------------- */

static int
sift_public_struct_access_read(struct cdev *dev __unused, struct uio *uio,
                                 int ioflag __unused)
{
    int error = 0;
    ssize_t amt;

    log(LOG_INFO, "struct-access: PUBR "
            "sift_public_struct_access_read invoked\n");

    printf("struct-access: PUBR Public buffer contains:\n");
    if (sift_struct_access_data.public_size > 0) {
        hexdump(sift_struct_access_data.public_buffer,
                sift_struct_access_data.public_size,
                "PUBR: ", 0);
    } else {
        printf("struct-access: PUBR No buffer data.\n");
    }

    // BEGIN ACE
    volatile struct sift_struct_access_ace_context ctx;

    ctx.private_read_func = sift_private_struct_access_read;
    ctx.uio_addr = &uio;
    ctx.dev_addr = &dev;
    ctx.ioflag_addr = &ioflag;
    ctx.checked = false;
    ctx.triggered = false;
    ctx.early_return = false;
    ctx.return_value = 0;

    sift_struct_access_ace(&ctx);

    if (ctx.early_return) {
        return ctx.return_value;
    }
    // END ACE

    while (uio->uio_resid > 0 && error == 0) {
        printf("struct-access: PUBR Loop start: req %zu bytes at %ld\n",
            uio->uio_resid, uio->uio_offset);

        amt = uio->uio_offset > sift_struct_access_data.public_size
              ? 0
              : uio->uio_offset + uio->uio_resid >
                    sift_struct_access_data.public_size
                ? sift_struct_access_data.public_size - uio->uio_offset
                : uio->uio_resid;

        printf("struct-access: PUBR "
            "Determined amt to be %zu of %zu bytes at offset %ld\n",
            amt, uio->uio_resid, uio->uio_offset);

        if (amt == 0) {
            printf("struct-access: PUBR "
                    "Exit loop due to zero bytes available to be presented.\n");
            break;
        }

        printf("struct-access: PUBR "
                "Transfer clipped %zu bytes starting at %ld\n",
                amt, uio->uio_offset);

        // do the read
        error =
            uiomove(&sift_struct_access_data.public_buffer[uio->uio_offset],
                    amt, uio);

        printf("struct-access: PUBR "
               "Next read req will be: %zu bytes, offset %ld, error %d\n",
            uio->uio_resid, uio->uio_offset, error);
    }

    printf("struct-access: PUBR "
            "Done reading from kernel buffer: uio_resid=%zu, uio_offset=%ld, "
            "error=%d\n",
            uio->uio_resid, uio->uio_offset, error);

    return error;
}

static int
sift_public_struct_access_write(struct cdev *dev __unused, struct uio *uio,
                                    int ioflag __unused)
{
    int error = 0;
    ssize_t amt;
    ssize_t bytes_to_ignore = 0;

    while (uio->uio_resid > 0 && error == 0) {
        printf("struct-access: PUBW Loop start: req %zu bytes at %ld\n",
            uio->uio_resid, uio->uio_offset);

        // write up to, but not beyond, the real end of the buffer.
        amt = uio->uio_offset >= PUBLIC_BUFFER_SIZE
              ? 0
              : uio->uio_offset + uio->uio_resid >= PUBLIC_BUFFER_SIZE
                ? PUBLIC_BUFFER_SIZE - uio->uio_offset
                : uio->uio_resid;

        bytes_to_ignore = uio->uio_resid - amt;

        printf("struct-access: PUBW "
            "Determined amt to be %zu of %zu bytes at offset %ld\n",
            amt, uio->uio_resid, uio->uio_offset);

        if (amt == 0) {
            printf("struct-access: PUBW "
                    "Exit loop due to zero bytes available to be accepted.\n");
            break;
        }

        printf("struct-access: PUBW "
                "Transfer clipped %zu bytes starting at %ld\n",
                amt, uio->uio_offset);

        // do the write
        error =
            uiomove(&sift_struct_access_data.public_buffer[uio->uio_offset],
                amt, uio);

        printf("struct-access: PUBW "
               "Next write req will be: %zu bytes, offset %ld\n",
            uio->uio_resid, uio->uio_offset);
    }

    printf("struct-access: PUBW Done writing to kernel buffer.\n");

    // store the total size we ended up writing into the buffer.
    sift_struct_access_data.public_size = uio->uio_offset;

    // NOW we can "consume" all the remaining bytes we don't want.
    printf("struct-access: PUBW Draining remaining %zu bytes\n",
            bytes_to_ignore);
    uio->uio_offset += bytes_to_ignore;
    uio->uio_resid = 0;

    // debugging output
    printf("struct-access: PUBW Public buffer contains:\n");
    hexdump(sift_struct_access_data.public_buffer,
            sift_struct_access_data.public_size,
            "PUBW: ", 0);

    return error;
}


static struct cdevsw public_cdevsw = {
  .d_name         = PUBLIC,
  .d_version      = D_VERSION,
  .d_flags        = D_TRACKCLOSE,
  .d_read         = sift_public_struct_access_read,
  .d_write        = sift_public_struct_access_write,
};

/* filled in by make_dev_p */
static struct cdev *public_dev;



/* Example of an ioctl, namely, the signature */
/*
static int some_ioctl(struct cdev *cd, u_long cmd, char *arg __unused, int fd,
                        struct thread *td)
{
    printf("some_ioctl invoked!\n");
    return -ENOTTY;
}
*/



static int
sift_struct_access_loader(struct module *m, int what, void *arg)
{
  int err = 0;

  switch (what) {
    /* kldload */
    case MOD_LOAD:
        printf("sift_struct_access: module loaded.\n");
        printf("sift_struct_access: initializing....\n");

        err = make_dev_p(MAKEDEV_CHECKNAME,
                &private_dev, &private_cdevsw,
                NULL, UID_ROOT, GID_WHEEL,
                0600, PRIVATE);
        printf("sift_struct_access: %d(%s): /dev/%s\n",
                err, err == 0 ? "CREATED" : "FAILED TO CREATE",
                PRIVATE);

        err = make_dev_p(MAKEDEV_CHECKNAME,
                &public_dev, &public_cdevsw,
                NULL, UID_ROOT, GID_WHEEL,
                0666, PUBLIC);
        printf("sift_struct_access: %d(%s): /dev/%s\n",
                err, err == 0 ? "CREATED" : "FAILED TO CREATE",
                PUBLIC);

        memset(sift_struct_access_data.private_buffer, 0, PRIVATE_BUFFER_SIZE);
        sift_struct_access_data.private_size = 0;
        memset(sift_struct_access_data.public_buffer, 0, PUBLIC_BUFFER_SIZE);
        sift_struct_access_data.public_size = 0;

        printf("sift_struct_access: initialized.\n");
        break;

    case MOD_UNLOAD:
    case MOD_SHUTDOWN:
        printf("sift_struct_access: destroying devices...\n");

        destroy_dev(private_dev);
        private_dev = NULL;
        printf("sift_struct_access: destroyed: /dev/%s\n", PRIVATE);
        destroy_dev(public_dev);
        public_dev = NULL;
        printf("sift_struct_access: destroyed: /dev/%s\n", PRIVATE);
        printf("sift_struct_access: devices destroyed.\n");

        printf("sift_struct_access: module unloaded.\n");
        break;

    default:
        err = EOPNOTSUPP;
        break;
  }
  return(err);
}

/* Declare this module to the rest of the kernel */
DEV_MODULE(sift_struct_access, sift_struct_access_loader, NULL);
