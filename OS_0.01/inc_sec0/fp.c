/*
 * kernel-space floating-point emulator
 * Rewritten for kernel-space integration by lyli.
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/bitops.h>
#include <linux/printk.h>
#include <linux/float.h>

typedef float FLOAT;

#define XUL 170141163178059628080016879768632819712.0f 

struct pdpfloat {
    u16 frac_hi; 
};

struct pdp_raw {
    u16 lo; 
    u16 hi; 
};

/* Externs required from main emulator */
extern u16 ispace[];
extern u16 dspace[];
extern s32 regs[];
extern int DST_MODE;
extern int DST_REG;
extern int PC;

extern void ll_word(u16 addr, u16 *out);
extern void lli_word(u16 addr, u16 *out);
extern void copylong(u16 dst, u16 src);
extern void load_src(void);
extern void store_dst(void);

extern u16 srcword;
extern u16 dstword;
extern s32 srclong;
extern s32 dstlong;

/* FPU condition flags */
static int FPC = 0;
static int FPZ = 0;
static int FPN = 0;
static int FPV = 0;
static int FPMODE = 0;
static int INTMODE = 0;

static FLOAT fregs[8];
static FLOAT Srcflt;
static struct pdp_raw tmp_pdp;
static int AC = 0;
static char *kfloat_buf = NULL;

/* Compose pdp_raw from bit components */
static inline struct pdp_raw pdp_make(u8 sign, u8 exp, u16 frac1, u16 frac2)
{
    struct pdp_raw r;
    r.hi = (u16)(((sign & 0x1) << 15) | ((exp & 0xff) << 7) | (frac1 & 0x7f));
    r.lo = frac2;
    return r;
}

/* Extract fields from pdp_raw */
static inline void pdp_extract(const struct pdp_raw *r, u8 *sign, u8 *exp, u16 *frac1, u16 *frac2)
{
    u16 hi = r->hi;
    *sign = (hi >> 15) & 0x1;
    *exp  = (hi >> 7) & 0xff;
    *frac1 = hi & 0x7f;
    *frac2 = r->lo;
}

/* Compute 2^n using repeated multiplication */
static FLOAT pow2f_by_int(int n)
{
    FLOAT r = 1.0f;
    if (n > 0) while (n-- > 0) r *= 2.0f;
    else while (n++ < 0) r *= 0.5f;
    return r;
}

/* Convert PDP-format float -> IEEE float */
static void from11float(FLOAT *out, const struct pdp_raw *in_raw)
{
    u8 sign, exp;
    u16 frac1, frac2;
    pdp_extract(in_raw, &sign, &exp, &frac1, &frac2);

    if (exp == 0 && frac1 == 0 && frac2 == 0) {
        *out = 0.0f;
        return;
    }

    int32_t exponent = (int32_t)exp - 128 - 24;
    uint32_t fraction = ((uint32_t)frac1 << 16) | (uint32_t)frac2;
    fraction += 8388608U; 

    FLOAT z = pow2f_by_int(exponent);
    *out = (FLOAT)fraction * z;
    if (sign) *out = -(*out);
}

/* Convert IEEE float -> PDP-format float */
static void to11float(const FLOAT *in, struct pdp_raw *out_raw)
{
    FLOAT infloat = *in;
    u8 sign = 0;
    if (infloat < 0.0f) { sign = 1; infloat = -infloat; }
    if (infloat == 0.0f) { *out_raw = pdp_make(0,0,0,0); return; }

    int exponent = 129;
    while (infloat >= 2.0f) { infloat *= 0.5f; exponent++; }
    while (infloat < 1.0f) { infloat *= 2.0f; exponent--; }

    infloat -= 1.0f;
    uint32_t fraction = (uint32_t)(infloat * 8388608.0f);
    u16 frac2 = (u16)(fraction & 0xffff);
    u16 frac1 = (u16)((fraction >> 16) & 0x7f);
    *out_raw = pdp_make(sign, (u8)exponent, frac1, frac2);
}

/* Handle illegal state */
static void illegal(void) { pr_err("kfloat: illegal addressing or state\n"); }

/* Load float into Srcflt based on DST_MODE */
static void load_flt(void)
{
    u16 indirect, addr;
    u16 *intptr;

 switch (DST_MODE) {
    case 0:
        if (DST_REG < 0 || DST_REG >= ARRAY_SIZE(fregs)) {
            Srcflt = 0.0f;
            return;
        }
        Srcflt = fregs[DST_REG];
        return;

    case 1:
        if (DST_REG == PC) {
            intptr = &ispace[regs[DST_REG]];
            tmp_pdp.lo = *intptr;
            tmp_pdp.hi = 0;
            from11float(&Srcflt, &tmp_pdp);
        } else {
            addr = regs[DST_REG];
            from11float(&Srcflt, (struct pdp_raw *)&dspace[addr]);
        }
        return;

    case 2:
        if (DST_REG == PC) {
            intptr = &ispace[regs[DST_REG]];
            tmp_pdp.lo = *intptr;
            tmp_pdp.hi = 0;
            from11float(&Srcflt, &tmp_pdp);
            regs[DST_REG] += 2;
        } else {
            addr = regs[DST_REG];
            from11float(&Srcflt, (struct pdp_raw *)&dspace[addr]);
            regs[DST_REG] += FPMODE ? 8 : 4;
        }
        return;

    case 3:
        ll_word(regs[DST_REG], &indirect);
        from11float(&Srcflt, (struct pdp_raw *)&dspace[indirect]);
        regs[DST_REG] += FPMODE ? 8 : 4;
        return;

    case 4:
        regs[DST_REG] -= FPMODE ? 8 : 4;
        addr = regs[DST_REG];
        from11float(&Srcflt, (struct pdp_raw *)&dspace[addr]);
        return;

    case 5:
        regs[DST_REG] -= FPMODE ? 8 : 4;
        ll_word(regs[DST_REG], &indirect);
        from11float(&Srcflt, (struct pdp_raw *)&dspace[indirect]);
        return;

    case 6:
        lli_word(regs[PC], &indirect);
        regs[PC] += 2;
        indirect = regs[DST_REG] + indirect;
        from11float(&Srcflt, (struct pdp_raw *)&dspace[indirect]);
        return;

    case 7:
        lli_word(regs[PC], &indirect);
        regs[PC] += 2;
        indirect = regs[DST_REG] + indirect;
        ll_word(indirect, &addr);
        from11float(&Srcflt, (struct pdp_raw *)&dspace[addr]);
        return;
}

illegal();


/* Save Srcflt to memory or register */
static void save_flt(void)
{
    u16 indirect, addr;
    struct pdp_raw local_pdp;

    switch (DST_MODE) {
    case 0: fregs[DST_REG]=Srcflt; return;
    case 1: 
        addr=regs[DST_REG]; 
        to11float(&Srcflt,&local_pdp);

         memcpy(&dspace[addr],&local_pdp,sizeof(local_pdp)); 
         return;
    case 2: 

        addr=regs[DST_REG]; 
        to11float(&Srcflt,&local_pdp);

         memcpy(&dspace[addr],&local_pdp,sizeof(local_pdp)); 
         regs[DST_REG]+=DST_REG==PC?2:(FPMODE?8:4); 
         return;
    case 3: 
        ll_word(regs[DST_REG],&indirect); 
        to11float(&Srcflt,&local_pdp); 
        memcpy(&dspace[indirect],&local_pdp,sizeof(local_pdp)); 
        regs[DST_REG]+=FPMODE?8:4; 
        return;

    case 4: 
        regs[DST_REG]-=FPMODE?8:4; 
        addr=regs[DST_REG]; to11float(&Srcflt,&local_pdp); 
        memcpy(&dspace[addr],&local_pdp,sizeof(local_pdp)); 
        return;

    case 5: 
        regs[DST_REG]-=FPMODE?8:4; 
        ll_word(regs[DST_REG],&indirect); 
        to11float(&Srcflt,&local_pdp); 
        memcpy(&dspace[indirect],&local_pdp,sizeof(local_pdp)); 
        return;

    case 6: lli_word(regs[PC],&indirect); regs[PC]+=2; 
        indirect=regs[DST_REG]+indirect; 
        to11float(&Srcflt,&local_pdp); 
        memcpy(&dspace[indirect],&local_pdp,sizeof(local_pdp)); 
        return;

    case 7: lli_word(regs[PC],&indirect); regs[PC]+=2; 
        indirect=regs[DST_REG]+indirect; 
        ll_word(indirect,&addr); 
        to11float(&Srcflt,&local_pdp); 
        memcpy(&dspace[addr],&local_pdp,sizeof(local_pdp)); 
        return;
    }
    illegal();
}


static void load_long(void)
{
    u16 addr, indirect;
    switch(DST_MODE){
    case 0: srclong=regs[DST_REG]; return;

    case 1: addr=regs[DST_REG]; 
        DST_REG==PC?copylong_from_ispace(`addr,&srclong):copylong_from_dspace(addr,&srclong); 
        return;

    case 2: addr=regs[DST_REG]; 
        DST_REG==PC?copylong_from_ispace(addr,&srclong):copylong_from_dspace(addr,&srclong); 
        regs[DST_REG]+=4; 
        return;

    case 3: 
        indirect=regs[DST_REG]; DST_REG==PC?lli_word(indirect,&addr):ll_word(indirect,&addr); 
        regs[DST_REG]+=4; 
        copylong_from_dspace(addr,&srclong); 
        return;

    case 4: 
        regs[DST_REG]-=4; 
        addr=regs[DST_REG]; 
        copylong_from_dspace(addr,&srclong); 
        return;
    case 5: 
        regs[DST_REG]-=4; 
        ll_word(regs[DST_REG],&addr); 
        copylong_from_dspace(addr,&srclong); 
        return;
    case 6: 
        lli_word(regs[PC],&indirect); 
        regs[PC]+=2; 
        addr=regs[DST_REG]+indirect; 
        copylong_from_dspace(addr,&srclong); 
        return;

    case 7: 
        lli_word(regs[PC],&indirect); 
        regs[PC]+=2; 
        indirect=regs[DST_REG]+indirect; 
        ll_word(indirect,&addr); 
        copylong_from_dspace(addr,&srclong); 
        return;
    }
    illegal();
}

static void store_long(void)
{
    u16 addr, indirect;

    switch(DST_MODE) {
        case 0:
            regs[DST_REG] = dstlong;
            return;

        case 1:
            addr = regs[DST_REG];
            copylong_to_dspace(addr, dstlong);
            return;

        case 2:
            addr = regs[DST_REG];
            copylong_to_dspace(addr, dstlong);
            regs[DST_REG] += 4;
            return;

        case 3:
            indirect = regs[DST_REG];
            ll_word(indirect, &addr);
            regs[DST_REG] += 4;
            copylong_to_dspace(addr, dstlong);
            return;

        case 4:
            regs[DST_REG] -= 4;
            addr = regs[DST_REG];
            copylong_to_dspace(addr, dstlong);
            return;

        case 5:
            regs[DST_REG] -= 4;
            ll_word(regs[DST_REG], &addr);
            copylong_to_dspace(addr, dstlong);
            return;

        case 6:
            lli_word(regs[PC], &indirect);
            regs[PC] += 2;
            addr = regs[DST_REG] + indirect;
            copylong_to_dspace(addr, dstlong);
            return;

        case 7:
            lli_word(regs[PC], &indirect);
            regs[PC] += 2;
            indirect = regs[DST_REG] + indirect;
            ll_word(indirect, &addr);
            copylong_to_dspace(addr, dstlong);
            return;
    }

    illegal();
}

/* FPU operations */
static void fpset(void)
{
}

static void ldf(void)
{
    AC = (0 >> 6) & 3;
    load_flt();
    fregs[AC] = Srcflt;
    FPC = 0;
    FPV = 0;
    FPZ = (fregs[AC] == 0.0f) ? 1 : 0;
    FPN = (fregs[AC] < 0.0f) ? 1 : 0;
}

static void stf(void)
{
    AC = (0 >> 6) & 3;
    Srcflt = fregs[AC];
    save_flt();
}

static void clrf(void)
{
    AC = (0 >> 6) & 3;
    Srcflt = 0.0f;
    save_flt();
    FPC = 0;
    FPV = 0;
    FPZ = 1;
}

static void addf(void)
{
    AC = (0 >> 6) & 3;
    load_flt();
    fregs[AC] += Srcflt;
    FPC = 0;
    FPV = (fregs[AC] > XUL) ? 1 : 0;
    FPZ = (fregs[AC] == 0.0f) ? 1 : 0;
    FPN = (fregs[AC] < 0.0f) ? 1 : 0;
}

static void subf(void)
{
    AC = (0 >> 6) & 3;
    load_flt();
    fregs[AC] -= Srcflt;
    FPC = 0;
    FPV = (fregs[AC] > XUL) ? 1 : 0;
    FPZ = (fregs[AC] == 0.0f) ? 1 : 0;
    FPN = (fregs[AC] < 0.0f) ? 1 : 0;
}

static void negf(void)
{
    load_flt();
    Srcflt = -Srcflt;
    save_flt();
    FPC = 0;
    FPV = 0;
    FPZ = (Srcflt == 0.0f) ? 1 : 0;
    FPN = (Srcflt < 0.0f) ? 1 : 0;
}

static void absf(void)
{
    load_flt();
    if (Srcflt < 0.0f)
        Srcflt = -Srcflt;
    save_flt();
    FPC = 0;
    FPV = 0;
    FPN = 0;
    FPZ = (Srcflt == 0.0f) ? 1 : 0;
}

static void mulf(void)
{
    AC = (0 >> 6) & 3;
    load_flt();
    fregs[AC] *= Srcflt;
    FPC = 0;
    FPV = (fregs[AC] > XUL) ? 1 : 0;
    FPZ = (fregs[AC] == 0.0f) ? 1 : 0;
    FPN = (fregs[AC] < 0.0f) ? 1 : 0;
}

static void moddf(void)
{
    FLOAT x, y;
    AC = (0 >> 6) & 3;
    load_flt();
    fregs[AC] *= Srcflt;
    y = fregs[AC];

    if (y > 0.0f)
        x = (FLOAT)__builtin_floorf(y);
    else
        x = (FLOAT)__builtin_ceilf(y);

    if ((AC | 1) < ARRAY_SIZE(fregs))
        fregs[AC | 1] = x;

    fregs[AC] = y - x;

    FPC = 0;
    FPV = (fregs[AC] > XUL) ? 1 : 0;
    FPZ = (fregs[AC] == 0.0f) ? 1 : 0;
    FPN = (fregs[AC] < 0.0f) ? 1 : 0;
}

static void divf(void)
{
    AC = (0 >> 6) & 3;
    load_flt();
    if (Srcflt == 0.0f) {
        FPV = 1;
        return;
    }
    fregs[AC] /= Srcflt;
    FPC = 0;
    FPV = (fregs[AC] > XUL) ? 1 : 0;
    FPZ = (fregs[AC] == 0.0f) ? 1 : 0;
    FPN = (fregs[AC] < 0.0f) ? 1 : 0;
}

static void cmpf(void)
{
    AC = (0 >> 6) & 3;
    load_flt();
    FPC = 0;
    FPV = 0;
    FPN = (fregs[AC] > Srcflt) ? 1 : 0;
    FPZ = (fregs[AC] == Srcflt) ? 1 : 0;
}

static void tstf(void)
{
    AC = (0 >> 6) & 3;
    load_flt();
    FPC = 0;
    FPV = 0;
    FPN = (Srcflt < 0.0f) ? 1 : 0;
    FPZ = (Srcflt == 0.0f) ? 1 : 0;
}

static void ldfps(void)
{
    load_src();
}

static void stfps(void)
{
    dstword = 0;
    store_dst();
}

static void lcdif(void)
{
    AC = (0 >> 6) & 3;
    if (INTMODE == 0) {
        load_src();
        fregs[AC] = (FLOAT)(s16)srcword;
    } else {
        load_long();
        fregs[AC] = (FLOAT)srclong;
    }
}

static void stcfi(void)
{
    AC = (0 >> 6) & 3;
    if (INTMODE == 0) {
        dstword = (s16)fregs[AC];
        store_dst();
    } else {
        dstlong = (s32)fregs[AC];
        store_long();
    }
}

static void stexp(void)
{
    struct pdp_raw pdptmp;
    AC = (0 >> 6) & 3;
    to11float(&fregs[AC], &pdptmp);
    dstword = ((pdptmp.hi >> 7) & 0xff) - 128;
    store_dst();
}

static void stcdf(void)
{
    FPMODE = 1 - FPMODE;
    stf();
    FPMODE = 1 - FPMODE;
}

static void ldcdf(void)
{
    AC = (0 >> 6) & 3;
    load_flt();
    fregs[AC] = Srcflt;
    FPC = 0;
    FPV = 0;
    FPZ = (fregs[AC] == 0.0f) ? 1 : 0;
    FPN = (fregs[AC] < 0.0f) ? 1 : 0;
}

/* 32-bit load/store helpers */
static inline void copylong_from_ispace(u16 addr, s32 *out)
{
    *out = (s32)((ispace[addr + 1] << 16) | ispace[addr]);
}

static inline void copylong_from_dspace(u16 addr, s32 *out)
{
    *out = (s32)((dspace[addr + 1] << 16) | dspace[addr]);
}

static inline void copylong_to_dspace(u16 addr, s32 val)
{
    dspace[addr] = (u16)(val & 0xffff);
    dspace[addr + 1] = (u16)((val >> 16) & 0xffff);
}
