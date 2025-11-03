/*
 * added kernel-safe memory management for expression nodes via `kmalloc()` and proper cleanup patterns.
 * rewritten by lyli.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>

#define CMSIZ 8192
#define TREESP 4096

enum {
	OP_0 = 0,
	LBRACK,
	PLUS,
	STAR,
	SIZEOF,
	AMPER,
	CALL,
	QUEST,
	COMMA,
	LOGAND,
	LOGOR,
	COLON,
	ARROW,
	DOT,
	CON,
	NAME,
	MCALL,
	INCBEF,
	DECBEF,
	INCAFT,
	DECAFT,
	LPARN,
	LBRACK_OP,
	RBRACK,
	RPARN,
	FSEL,
	LESSEQ,
	LESSEQP, /* used in original op adjustment */
	MINUS,
	NEG,
};

#define OP_B_BINARY   (1<<0)  /* binary operator */
#define OP_B_LVALUE   (1<<1)  /* operator requires lvalue */
#define OP_B_LWORD    (1<<2)
#define OP_B_RWORD    (1<<3)
#define OP_B_ASSGOP   (1<<4)
#define OP_B_RELAT    (1<<5)

#define BINARY   OP_B_BINARY
#define LVALUE   OP_B_LVALUE
#define LWORD    OP_B_LWORD
#define RWORD    OP_B_RWORD
#define ASSGOP   OP_B_ASSGOP
#define RELAT    OP_B_RELAT

/* Type system placeholders */
enum {
	NOTYPE = 0,
	INT,
	DOUBLE,
	CHAR,
	STRUCT,
	FUNC = 0x100,   /* XTYPE marker: lower bits indicate base; upper bits indicate categories */
	PTR  = 0x200,
	ARRAY = 0x400,
};

#define ITP 1
#define PTI 2
#define XX  3

/* limits */
#define NCPW 4


struct tnode {
	int op;
	int type;
	int dimp;
	long value;           /* integer constant value */
	int class;            /* MOS/FMOS etc. */
	int ssp;              /* used by struct member selection in original */
	int nloc;             /* local index for member offset */
	struct tnode *tr1;    /* left/child pointer used by original structures */
	struct tnode *tr2;    /* optional second child */
};

static struct tnode *cmst[CMSIZ];
static struct tnode **cp = cmst + CMSIZ; /* initial cp points past the end (stack grows down) */

/* treespace placeholder (original used integer based treespace) */
static int treespace[TREESP];
static int opdope[1024];  /* indexed by op value */

/* cvtab / lintyp helper tables (stubs) */
static int cvtab[16][16];    /* conversion table stub */
static inline int lintyp(int t) { return (t & 0xff); } /* stub: map type to index */


static struct tnode *block(int nargs, int op, int type, int dimp, ...);
static struct tnode *convert(struct tnode *p, int t, int cvn, int otherlen);
static int plength(struct tnode *p);
static struct tnode *disarray(struct tnode *p);
static struct tnode *chkfun(struct tnode *p);
static int chkw(struct tnode *p, int flag);
static int chklval(struct tnode *p);
static int length(struct tnode *p);
static int incref(int t);
static int decref(int t);
static int fold(int op, struct tnode *p1, struct tnode *p2);


static struct tnode *tnode_alloc(void)
{
	struct tnode *p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		pr_err("kbuild: tnode_alloc: kmalloc failed\n");
	return p;
}

static struct tnode *block(int nargs, int op, int type, int dimp, ...)
{
	va_list ap;
	struct tnode *res;

	res = tnode_alloc();
	if (!res)
		return NULL;

	res->op = op;
	res->type = type;
	res->dimp = dimp;

	va_start(ap, dimp);
	if (nargs >= 1)
		res->tr1 = va_arg(ap, struct tnode *);
	if (nargs >= 2)
		res->tr2 = va_arg(ap, struct tnode *);
	va_end(ap);

	if (debug)
		pr_info("kbuild: block() op=%d type=%d dimp=%d\n", op, type, dimp);

	return res;
}

static struct tnode *convert(struct tnode *p, int t, int cvn, int otherlen)
{
	if (!p) return NULL;
	pr_info_once("kbuild: convert() stub used - implement real conversion\n");
	return p;
}

static int plength(struct tnode *p)
{
	/* conservative default */
	if (!p)
		return 0;
	return 1;
}

/* disarray: placeholder - returns same pointer */
static struct tnode *disarray(struct tnode *p)
{
	/* original used to collapse array references */
	return p;
}

/* chkfun: placeholder to check for function usage */
static struct tnode *chkfun(struct tnode *p)
{
	/* in real compiler, would check for calling function pointers etc. */
	return p;
}

/* chkw: check long/word qualifiers - stub returns 0 */
static int chkw(struct tnode *p, int flag)
{
	(void)p; (void)flag;
	return 0;
}

/* chklval: check that p is an lvalue - stub returns 0 (no error) */
static int chklval(struct tnode *p)
{
	(void)p;
	/* real implementation should validate */
	return 0;
}

static int length(struct tnode *p)
{
	(void)p;
	/* assume size of int */
	return sizeof(int);
}

/* incref/decref: pointer type helpers (placeholder) */
static int incref(int t)
{
	/* in original, incref adds pointer indirection */
	return t + PTR;
}
static int decref(int t)
{
	if (t >= PTR) return t - PTR;
	return t;
}

/* fold: constant folding stub */
static int fold(int op, struct tnode *p1, struct tnode *p2)
{
	(void)op; (void)p1; (void)p2;
	/* not implemented: return 0 to indicate no folding */
	return 0;
}

void build(int op)
{
	int t1;
	int t2, t3, t;
	struct tnode *p3 = NULL;
	struct tnode *p1, *p2;
	int d, dope, leftc, cvn, pcvn;

	if (op == LBRACK) {
		/* original: build(PLUS); op = STAR; */
		build(PLUS);
		op = STAR;
	}

	/* ensure cp within bounds */
	if (cp <= cmst || cp > cmst + CMSIZ) {
		pr_err("kbuild: stack pointer cp out of bounds\n");
		return;
	}

	dope = opdope[op];

	if ((dope & BINARY) != 0) {
		p2 = *--cp;
		if (!p2) {
			pr_err("kbuild: missing right operand\n");
			return;
		}
		p2 = disarray(p2);
		p2 = chkfun(p2);
		t2 = p2->type;
	} else {
		p2 = NULL;
	}

	/* p1 = *--cp; */
	p1 = *--cp;
	if (!p1) {
		pr_err("kbuild: missing left operand\n");
		return;
	}

	if (op == SIZEOF) {
		t1 = length(p1);
		p1->op = CON;
		p1->type = INT;
		p1->dimp = 0;
		p1->value = t1;
		*cp++ = p1;
		return;
	}

	if (op != AMPER) {
		p1 = disarray(p1);
		if (op != CALL)
			p1 = chkfun(p1);
	}
	t1 = p1->type;
	pcvn = 0;
	t = INT;

	switch (op) {
	case 0:
		*cp++ = p1;
		return;

	case QUEST:
		if (!p2 || p2->op != COLON) {
			pr_err("kbuild: Illegal conditional\n");
			/* push something conservative */
			*cp++ = p1;
			return;
		}
		t = t2;
		/* fall through to comma-like handling */
	case COMMA:
	case LOGAND:
	case LOGOR:
		*cp++ = block(2, op, t, 0, p1, p2);
		return;

	case CALL:
		/* if ((t1&XTYPE) != FUNC) error("Call of non-function"); */
		if ((t1 & FUNC) != FUNC) {
			pr_err("kbuild: Call of non-function (type=%d)\n", t1);
			/* still produce a node */
		}
		*cp++ = block(2, CALL, decref(t1), p1->dimp, p1, p2);
		return;

	case STAR:
		if (p1->op == AMPER) {
			/* *&x -> x->tr1? */
			*cp++ = p1->tr1;
			return;
		}
		if ((t1 & FUNC) == FUNC) {
			pr_err("kbuild: Illegal indirection of function\n");
		}
		*cp++ = block(1, STAR, decref(t1), p1->dimp, p1);
		return;

	case AMPER:
		if (p1->op == STAR) {
			p1->tr1->dimp = p1->dimp;
			p1->tr1->type = incref(t1);
			*cp++ = p1->tr1;
			return;
		}
		if (p1->op == NAME) {
			*cp++ = block(1, AMPER, incref(t1), p1->dimp, p1);
			return;
		}
		pr_err("kbuild: Illegal lvalue for & operator\n");
		break;

	case ARROW:
		/* a->b  => (*a).b */
		*cp++ = p1;
		chkw(p1, -1);
		p1->type = PTR + STRUCT; /* symbolic */
		build(STAR);
		p1 = *--cp;
		/* fall through to DOT handling */

	case DOT:
		if (!p2 || p2->op != NAME || (p2->class != /*MOS*/0 && p2->class != /*FMOS*/0)) {
			pr_err("kbuild: Illegal structure reference\n");
			*cp++ = p1;
			return;
		}
		*cp++ = p1;
		t = t2;
		if ((t & ARRAY) == ARRAY) {
			t = decref(t);
			p2->ssp++;
		}

		build(AMPER);
		*cp++ = block(1, CON, NOTYPE, 0, p2); /* placeholder */
		build(PLUS);
		if ((t2 & ARRAY) != ARRAY)
			build(STAR);
		if (p2->class == /*FMOS*/0)
			*cp++ = block(2, FSEL, t, 0, *--cp, (struct tnode*) (long)p2->dimp);
		return;
	}

	if ((dope & LVALUE) != 0)
		chklval(p1);
	if ((dope & LWORD) != 0)
		chkw(p1, /*LONG*/0);
	if ((dope & RWORD) != 0)
		chkw(p2, /*LONG*/0);

	if ((dope & BINARY) == 0) {
		if (op == /*ITOF*/0)
			t1 = DOUBLE;
		else if (op == /*FTOI*/0)
			t1 = INT;
		if (!fold(op, p1, NULL))
			*cp++ = block(1, op, t1, p1->dimp, p1);
		return;
	}

	cvn = 0;
	if (t1 == STRUCT || (p2 && p2->type == STRUCT)) {
		pr_err("kbuild: Unimplemented structure operation\n");
		t1 = t2 = INT;
	}
	if (p2 && p2->type == NOTYPE) {
		t = t1;
		p2->type = INT;
		t2 = INT;
	} else if (p2) {
		cvn = cvtab[lintyp(t1)][lintyp(t2)];
	} else {
		cvn = 0;
	}
	leftc = (cvn >> 4) & 017;
	cvn &= 017;
	t = leftc ? t2 : t1;

	if (dope & ASSGOP) {
		t = t1;
		if (op == /*ASSIGN*/0 && (cvn == ITP || cvn == PTI))
			cvn = leftc = 0;
		if (leftc)
			cvn = leftc;
		leftc = 0;
	} else if (op == COLON && t1 >= PTR && t1 == t2) {
		cvn = 0;
	} else if (dope & RELAT) {
		if (op >= LESSEQ && (t1 >= PTR || (p2 && t2 >= PTR)))
			/* op =+ LESSEQP-LESSEQ; */ /* historic operator adjustment */
			op = LESSEQP; /* placeholder */
		if (cvn == PTI)
			cvn = 0;
	}

	if (cvn == PTI) {
		cvn = 0;
		if (op == MINUS) {
			t = INT;
			pcvn++;
		} else {
			if (t1 != (p2 ? p2->type : t1) || t1 != (PTR + CHAR))
				cvn = XX;
		}
	}

	if (cvn) {
		t1 = plength(p1);
		t2 = plength(p2);
		if (cvn == XX || (cvn == PTI && t1 != t2))
			pr_err("kbuild: Illegal conversion\n");
		else if (leftc)
			p1 = convert(p1, t, cvn, t2);
		else
			p2 = convert(p2, t, cvn, t1);
	}

	if (dope & RELAT)
		t = INT;

	if (!fold(op, p1, p2)) {
		/* choose dimp based on p1/p2 per original logic */
		int chosen_d = (p1->dimp == 0) ? (p2 ? p2->dimp : 0) : p1->dimp;
		*cp++ = block(2, op, t, chosen_d, p1, p2);
	}
	if (pcvn && t1 != (PTR + CHAR)) {
		p1 = *--cp;
		*cp++ = convert(p1, 0, PTI, plength(p1->tr1));
	}
}

int debug = 0;
EXPORT_SYMBOL(debug);


MODULE_LICENSE("GPL");
