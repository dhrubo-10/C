#ifndef FILEPS_H
#define FILEPS_H

#include <stddef.h>
#include <stdint.h>

struct fileps {
    char  *buff;      
    char  *bptr;   
    int    nchars;    
    int    bsize;     
    char   eoferr;    
    char   wrflag;    
};

extern struct fileps IEH3fpts[10];
extern int IEHfbak[10];

#endif
