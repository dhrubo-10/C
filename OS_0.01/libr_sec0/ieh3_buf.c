#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "i3_hc.h"

#define IEH3BSZ 512

struct fileps IEH3fpts[10];
int IEHfbak[10];
char *IEH3olbf[10];

/*
 * Return 'x' if file descriptor is a terminal.
 * Original code used ttyn(fn) == 'x';
 * Here we keep compatibility by providing safe equivalent.
 */
static int is_terminal(int fd)
{
    return isatty(fd);
}

/*
 * Modern, fixed version of IEH3mbuf().
 */
void IEH3mbuf(int fn, int type)
{
    struct fileps *fp;
    struct stat st;

    if (fn < 0 || fn >= 10)
        return;

    fp = &IEH3fpts[fn];

    fp->eoferr = 0;
    fp->nchars = 0;
    fp->wrflag = type + 1;

    int size;

    /* Choose buffer size based on TTY + file type */
    if (!is_terminal(fn)) {
        size = 1;
    } else if (fstat(fn, &st) == 0 && S_ISREG(st.st_mode) && type == 0) {
        size = 1;
    } else {
        size = IEH3BSZ;
    }

    fp->buff = NULL;

    /*
     * Try allocating a buffered block
     * Original: alloc(size+100) and retry with size/=4
     */
    while (size > 10 && fp->buff == NULL) {

        char *mem = malloc(size + 100);
        if (mem) {
            IEH3olbf[fn] = mem;
            fp->buff = mem + 100;
            fp->bptr = fp->buff;
            fp->bsize = size;
            break;
        }

        size /= 4;
    }

    
    if (!fp->buff) {
        fp->buff = (char *)&IEHfbak[fn];
        fp->bptr = fp->buff;
        fp->bsize = (size > 1) ? 2 : 1;
    }
}
