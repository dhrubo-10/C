#include <math.h>
#ifdef HAVE_POWF
float powf(float x, float y);
#else
# define powf(x,y) (float)pow((double)x, (double)y)
#endif

#define XUL	170141163178059628080016879768632819712.0

typedef struct {
   unsigned frac1:7;
   unsigned exp:  8;
   unsigned sign: 1;
   unsigned frac2: 16;
} pdpfloat;

FLOAT  fregs[8];
int FPC=0;
int FPZ=0;
int FPN=0;
int FPV=0;
int FPMODE=0;
int INTMODE=0;

FLOAT Srcflt;
pdpfloat *fladdr;
int   AC;
int32_t srclong;
int32_t dstlong;
static char *buf, *buf2;

static void from11float(FLOAT *out, pdpfloat *in)
{
 int32_t  exponent;
 u_int32_t fraction;
 FLOAT z;

 exponent= in->exp - 128 - 24;
 fraction= (in->frac1 << 16) + in->frac2 + 8388608;

 z= powf(2.0, (float)exponent);
 *out= (float)fraction * z;
 if (in->sign) *out= -(*out);
}

static void to11float(FLOAT *in, pdpfloat *out)
{
  int32_t  exponent=129;
  u_int32_t fraction;
  FLOAT infloat= *in;

  if (infloat < 0.0) { out->sign=1; infloat= -infloat; } 
  else out->sign=0;

  if (infloat==0.0) { out->frac1=0; out->frac2=0; out->exp=0; return; }

  while (infloat >= 2.0) { infloat *= 0.5; exponent++; }
  while (infloat < 1.0)	 { infloat *= 2.0; exponent--; }

  infloat= infloat - 1.0;
  fraction= (int)(infloat * 8388608.0);
  out->frac2= fraction & 0xffff;
  out->frac1= (fraction>>16);
  out->exp= exponent;
}

static struct { u_int16_t lo; u_int16_t hi; } intpair;

static void load_flt(void)
{
    u_int16_t indirect,addr;
    u_int16_t *intptr;

    switch (DST_MODE) {
    case 0:
	Srcflt = fregs[DST_REG];
	fladdr=NULL; return;
    case 1:
	if (DST_REG == PC) {
	    intptr = (u_int16_t *)&ispace[regs[DST_REG]];
	    intpair.lo= *intptr;
	    intpair.hi=0;
	    fladdr= (pdpfloat *)&intpair;
	} else fladdr = (pdpfloat *)&dspace[regs[DST_REG]];
	from11float(&Srcflt, fladdr);
	return;
    case 2:
	if (DST_REG == PC) {
	    intptr = (u_int16_t *)&ispace[regs[DST_REG]];
	    intpair.lo= *intptr;
	    intpair.hi=0;
	    fladdr= (pdpfloat *)&intpair;
	    from11float(&Srcflt, fladdr);
	    regs[DST_REG] += 2;
	} else {
	    fladdr = (pdpfloat *)&dspace[regs[DST_REG]];
	    from11float(&Srcflt, fladdr);
	    if (FPMODE) regs[DST_REG] += 8;
	    else regs[DST_REG] += 4;
	}
	return;
    case 3:
	ll_word(regs[DST_REG], indirect);
	if (DST_REG == PC) {
	    intptr = (u_int16_t *)&ispace[indirect];
	    intpair.lo= *intptr;
	    intpair.hi=0;
	    fladdr= (pdpfloat *)&intpair;
	    from11float(&Srcflt, fladdr);
	    regs[DST_REG] += 2;
	} else {
	    fladdr = (pdpfloat *)&dspace[indirect];
	    from11float(&Srcflt, fladdr);
	    if (FPMODE) regs[DST_REG] += 8;
	    else regs[DST_REG] += 4;
	}
	return;
    case 4:
	if (FPMODE) regs[DST_REG] -= 8;
	else regs[DST_REG] -= 4;
	fladdr = (pdpfloat *)&dspace[regs[DST_REG]];
	from11float(&Srcflt, fladdr);
	return;
    case 5:
	if (FPMODE) regs[DST_REG] -= 8;
	else regs[DST_REG] -= 4;
	ll_word(regs[DST_REG], indirect);
	fladdr = (pdpfloat *)&dspace[indirect];
	from11float(&Srcflt, fladdr);
	return;
    case 6:
	lli_word(regs[PC], indirect);
	regs[PC] += 2;
	indirect= regs[DST_REG] + indirect;
	fladdr = (pdpfloat *)&dspace[indirect];
	from11float(&Srcflt, fladdr);
	return;
    case 7:
	lli_word(regs[PC], indirect);
	regs[PC] += 2;
	indirect = regs[DST_REG] + indirect;
	ll_word(indirect, addr);
	fladdr = (pdpfloat *)&dspace[addr];
	from11float(&Srcflt, fladdr);
	return;
    }
    illegal();
}

static void save_flt(void)
{
    u_int16_t indirect;
    u_int16_t addr;
    pdpfloat *fladdr;

    switch (DST_MODE) {
    case 0:
	fregs[DST_REG] = Srcflt;
	return;
    case 1:
	fladdr = (pdpfloat *)&dspace[regs[DST_REG]];
	to11float(&Srcflt, fladdr);
	return;
    case 2:
	fladdr = (pdpfloat *)&dspace[regs[DST_REG]];
	to11float(&Srcflt, fladdr);
	if (DST_REG == PC) regs[DST_REG] += 2;
	else if (FPMODE) regs[DST_REG] += 8;
	else regs[DST_REG] += 4;
	return;
    case 3:
	ll_word(regs[DST_REG], indirect);
	fladdr = (pdpfloat *)&dspace[indirect];
	to11float(&Srcflt, fladdr);
	if (DST_REG == PC) regs[DST_REG] += 2;
	else if (FPMODE) regs[DST_REG] += 8;
	else regs[DST_REG] += 4;
	return;
    case 4:
	if (FPMODE) regs[DST_REG] -= 8;
	else regs[DST_REG] -= 4;
	fladdr = (pdpfloat *)&dspace[regs[DST_REG]];
	to11float(&Srcflt, fladdr);
	return;
    case 5:
	if (FPMODE) regs[DST_REG] -= 8;
	else regs[DST_REG] -= 4;
	ll_word(regs[DST_REG], indirect);
	fladdr = (pdpfloat *)&dspace[indirect];
	to11float(&Srcflt, fladdr);
	return;
    case 6:
	lli_word(regs[PC], indirect);
	regs[PC] += 2;
	indirect = regs[DST_REG] + indirect;
	fladdr = (pdpfloat *)&dspace[indirect];
	to11float(&Srcflt, fladdr);
	return;
    case 7:
	lli_word(regs[PC], indirect);
	regs[PC] += 2;
	indirect = regs[DST_REG] + indirect;
	ll_word(indirect, addr);
	fladdr = (pdpfloat *)&dspace[addr];
	to11float(&Srcflt, fladdr);
	return;
    }
    illegal();
}

#define lli_long(addr, word) \
	{ adptr= (u_int16_t *)&(ispace[addr]); copylong(word, *adptr); } \

#define ll_long(addr, word) \
	{ adptr= (u_int16_t *)&(dspace[addr]); copylong(word, *adptr); } \

#define sl_long(addr, word) \
	{ adptr= (u_int16_t *)&(dspace[addr]); copylong(*adptr, word); } \

static void load_long(void)
{
    u_int16_t addr, indirect;

    switch (DST_MODE) {
    case 0:
	srclong = regs[DST_REG];
	return;
    case 1:
	addr = regs[DST_REG];
	if (DST_REG == PC) {
	    lli_long(addr, srclong)
	} else {
	    ll_long(addr, srclong);
	}
	return;
    case 2:
	addr = regs[DST_REG];
	if (DST_REG == PC) {
	    lli_long(addr, srclong)
	} else {
	    ll_long(addr, srclong);
	}
	regs[DST_REG] += 4;
	return;
    case 3:
	indirect = regs[DST_REG];
	if (DST_REG == PC) {
	    lli_word(indirect, addr)
	} else {
	    ll_word(indirect, addr);
	}
	regs[DST_REG] += 4;
	ll_long(addr, srclong);
	return;
    case 4:
	regs[DST_REG] -= 4;
	addr = regs[DST_REG];
	ll_long(addr, srclong);
	return;
    case 5:
	regs[DST_REG] -= 4;
	indirect = regs[DST_REG];
	ll_word(indirect, addr);
	ll_long(addr, srclong);
	return;
    case 6:
	lli_word(regs[PC], indirect);
	regs[PC] += 2;
	addr = regs[DST_REG] + indirect;
	ll_long(addr, srclong);
	return;
    case 7:
	lli_word(regs[PC], indirect);
	regs[PC] += 2;
	indirect = regs[DST_REG] + indirect;
	ll_word(indirect, addr);
	ll_long(addr, srclong);
	return;
    }
    illegal();
}

static void store_long(void)
{
    u_int16_t addr, indirect;

    switch (DST_MODE) {
    case 0:
	regs[DST_REG]= dstlong;
	return;
    case 1:
	addr = regs[DST_REG];
	sl_long(addr, dstlong)
	return;
    case 2:
	addr = regs[DST_REG];
	sl_long(addr, dstlong)
	regs[DST_REG] += 4;
	return;
    case 3:
	indirect = regs[DST_REG];
	ll_word(indirect, addr);
	regs[DST_REG] += 4;
	sl_long(addr, dstlong);
	return;
    case 4:
	regs[DST_REG] -= 4;
	addr = regs[DST_REG];
	sl_long(addr, dstlong);
	return;
    case 5:
	regs[DST_REG] -= 4;
	indirect = regs[DST_REG];
	ll_word(indirect, addr);
	sl_long(addr, dstlong);
	return;
    case 6:
	lli_word(regs[PC], indirect);
	regs[PC] += 2;
	addr = regs[DST_REG] + indirect;
	sl_long(addr, dstlong);
	return;
    case 7:
	lli_word(regs[PC], indirect);
	regs[PC] += 2;
	indirect = regs[DST_REG] + indirect;
	ll_word(indirect, addr);
	sl_long(addr, dstlong);
	return;
    }
    illegal();
}

void fpset()
{
    switch (ir) {
	case 0170000:
	CC_C= FPC; CC_V= FPV;
	CC_Z= FPZ; CC_N= FPN;
	return;
    case 0170001:
	FPMODE=0; return;
    case 0170002:
	INTMODE=0; return;
    case 0170011:
	FPMODE=1; return;
    case 0170012:
	INTMODE=1; return;
    default:
	not_impl();
    }
}

void ldf()
{
  AC= (ir >> 6) & 3;
  load_flt();
  fregs[AC]= Srcflt;
  FPC=0; FPV=0; 
  if (fregs[AC]==0.0) FPZ=1; else FPZ=0;
  if (fregs[AC]<0.0)  FPN=1; else FPN=0;
}

void stf()
{
  AC= (ir >> 6) & 3;
  Srcflt= fregs[AC];
  save_flt();
}

void clrf()
{
  AC= (ir >> 6) & 3;
  Srcflt= 0.0;
  save_flt();
  FPC= FPZ= FPV= 0; FPZ=1;
}

void addf()
{
  AC= (ir >> 6) & 3;
  load_flt();
  fregs[AC]+= Srcflt;
  FPC=0;
  if (fregs[AC]>XUL)  FPV=1; else FPV=0;
  if (fregs[AC]==0.0) FPZ=1; else FPZ=0;
  if (fregs[AC]<0.0)  FPN=1; else FPN=0;
}

void subf()
{
  AC= (ir >> 6) & 3;
  load_flt();
  fregs[AC]-= Srcflt;
  FPC=0;
  if (fregs[AC]>XUL)  FPV=1; else FPV=0;
  if (fregs[AC]==0.0) FPZ=1; else FPZ=0;
  if (fregs[AC]<0.0)  FPN=1; else FPN=0;
}

void negf()
{
  load_flt();
  fladdr->sign= -(fladdr->sign);
  FPC=0; FPV=0; 
  if (Srcflt==0.0) FPZ=1; else FPZ=0;
  if (Srcflt<0.0)  FPN=1; else FPN=0;
}

void absf()
{
  load_flt();
  fladdr->sign= 0;
  FPC=0; FPV=0; FPN=0;
  if (Srcflt==0.0) FPZ=1; else FPZ=0;
}

void mulf()
{
  AC= (ir >> 6) & 3;
  load_flt();
  fregs[AC]*= Srcflt;
  FPC=0;
  if (fregs[AC]>XUL)  FPV=1; else FPV=0;
  if (fregs[AC]==0.0) FPZ=1; else FPZ=0;
  if (fregs[AC]<0.0)  FPN=1; else FPN=0;
}

void moddf()
{
  FLOAT x,y;

  AC= (ir >> 6) & 3;
  load_flt();
  fregs[AC]*= Srcflt; y= fregs[AC];
  if (y>0.0) x= (FLOAT) floor((double)y);
  else x= (FLOAT) ceil((double)y);
  fregs[AC|1]= x;

  y=y-x;  fregs[AC]=y;

  FPC=0;
  if (fregs[AC]>XUL)  FPV=1; else FPV=0;
  if (fregs[AC]==0.0) FPZ=1; else FPZ=0;
  if (fregs[AC]<0.0)  FPN=1; else FPN=0;
}

void divf()
{
  AC= (ir >> 6) & 3;
  load_flt();
  fregs[AC]/= Srcflt;
  FPC=0;
  if (fregs[AC]>XUL)  FPV=1; else FPV=0;
  if (fregs[AC]==0.0) FPZ=1; else FPZ=0;
  if (fregs[AC]<0.0)  FPN=1; else FPN=0;
}

void cmpf()
{
  AC= (ir >> 6) & 3;
  load_flt();
  FPC=0; FPV=0;
  if (fregs[AC]>Srcflt)	 FPN=1; else FPN=0;
  if (fregs[AC]==Srcflt) FPZ=1; else FPZ=0;
}

void tstf()
{
  AC= (ir >> 6) & 3;
  load_flt();
  FPC=0; FPV=0;
  if (Srcflt<0.0)  FPN=1; else FPN=0;
  if (Srcflt==0.0) FPZ=1; else FPZ=0;
}

void ldfps()
{
    load_dst();
    if (dstword & CC_NBIT) CC_N=1;
    if (dstword & CC_ZBIT) CC_Z=1;
    if (dstword & CC_VBIT) CC_V=1;
    if (dstword & CC_CBIT) CC_C=1;
}

void stfps()
{
    srcword=0;
    if (CC_N) srcword|= CC_NBIT;
    if (CC_Z) srcword|= CC_ZBIT;
    if (CC_V) srcword|= CC_VBIT;
    if (CC_C) srcword|= CC_CBIT;
    store_dst();
}

void lcdif()
{
  AC= (ir >> 6) & 3;
  if (INTMODE==0) {
	load_src();
	fregs[AC]= (float) srcword;
  } else {
	load_long();
	fregs[AC]= (float) srclong;
  }
}

void stcfi()
{
  AC= (ir >> 6) & 3;
  if (INTMODE==0) {
	dstword= (int16_t) fregs[AC];
	store_dst();
  } else {
	dstlong= (int32_t) fregs[AC];
	store_long();
  }
}

void stexp()
{
 pdpfloat pdptmp;

 AC= (ir >> 6) & 3;
 to11float(&fregs[AC], &pdptmp);
 dstword= pdptmp.exp - 128;
 store_dst();
}

void stcdf()
{
 FPMODE=1 - FPMODE; stf(); FPMODE=1 - FPMODE;
}


/* Load a double-precision floating-point value from memory into the FPU register */
void ldcdf()
{
 		AC = (ir >> 6) & 3;   /* Get the accumulator field */
    load_flt();            /* Load the source float from memory */
    fregs[AC] = Srcflt;    /* Store it in the FPU register */
    FPC = 0; FPV = 0;      /* Reset flags */
    FPZ = (fregs[AC] == 0.0) ? 1 : 0;
    FPN = (fregs[AC] < 0.0) ? 1 : 0;
}


/* Store FPU status (no-op / placeholder) */

void stst()
{
		/* Optionally, store FPU condition codes or other status to memory */
    /* For now, just clear the flags as a placeholder */
    FPC = 0;
    FPZ = 0;
    FPN = 0;
    FPV = 0;
}

void ldexpp()
{
 pdpfloat pdptmp;

 AC= (ir >> 6) & 3;
 to11float(&fregs[AC], &pdptmp);
 load_src();
 srcword +=128;
 srcword &= 0xff;
 pdptmp.exp= srcword;
 from11float(&fregs[AC], &pdptmp);
}
