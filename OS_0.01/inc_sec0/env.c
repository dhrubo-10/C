/*
 * Rewrote this code. Would cause issues Issues. - lyl
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/err.h>
#include <linux/param.h>

MODULE_AUTHOR("Lyli");
MODULE_DESCRIPTION("Kernel-space lexer/parser rewrite");
MODULE_LICENSE("GPL");

static char *input_path = NULL;
module_param(input_path, charp, 0444);
MODULE_PARM_DESC(input_path, "Path to input file to lex (in kernel)");

static int debug = 0;
module_param(debug, int, 0444);
MODULE_PARM_DESC(debug, "Enable debug logging");

#define STRSIZ      4096
#define NCPS        64
#define HSZ         1024
#define READBUF_SZ  4096
#define CMSIZ       8192

static int isn = 1;
static int peeksym = -1;
static int line_no = 1;
static int eof_flag = 0;
static int inhdr = 0;
static int mosflg = 0;
static int proflg = 0;

static char savstr[STRSIZ];
static char *strptr = savstr;
static int nchstr = 0;

/* symbol buffer */
static char symbuf[NCPS];
static size_t ncps = NCPS;

/* peek char and file reader state */
static int peekc = 0;

/* token/value containers */
static int cval;       /* integer token value or constant index */
static long fcval_int; /* store integer part for float stub */
static int current_token = 0;

enum {
    TOK_NAME = 256,
    TOK_KEYW,
    TOK_FCON,
    TOK_CON,
    TOK_SFCON,
    TOK_STRING,
    TOK_INCBEF,
    TOK_DECBEF,
    TOK_INCAFT,
    TOK_DECAFT,
    TOK_EXCLA,
    TOK_DIVIDE,
    TOK_PLUS,
    TOK_MINUS,
    TOK_ASSIGN,
    TOK_AND,
    TOK_OR,
    TOK_LETTER,
    TOK_DIGIT,
    TOK_DQUOTE,
    TOK_SQUOTE,
    TOK_EOF
};

/* Small hash table entry */
struct hshtab {
    char name[NCPS];
    unsigned int hflag;
    unsigned int hclass;
    unsigned int htype;
    unsigned long hoffset;
    unsigned int dimp;
};

static struct hshtab *hshtab; /* allocated at init */
static size_t hshsiz = HSZ;
static size_t hshused = 0;
struct kwtab {
    const char *kwname;
    int kwval;
};

static struct kwtab kwtab[] = {
    { "int",     1 },
    { "char",    2 },
    { "float",   3 },
    { "double",  4 },
    { "struct",  5 },
    { "long",    6 },
    { "auto",    7 },
    { "extern",  8 },
    { "static",  9 },
    { "register",10 },
    { "goto",    11 },
    { "return",  12 },
    { "if",      13 },
    { "while",   14 },
    { "else",    15 },
    { "switch",  16 },
    { "case",    17 },
    { "break",   18 },
    { "continue",19 },
    { "do",      20 },
    { "default", 21 },
    { "for",     22 },
    { "sizeof",  23 },
    { NULL,      0 }
};

struct kreader {
    struct file *file;
    loff_t pos;
    char *buf;
    size_t buf_len;
    size_t buf_pos;
    ssize_t buf_valid;
};

static struct kreader kr = {
    .file = NULL,
    .pos = 0,
    .buf = NULL,
    .buf_len = READBUF_SZ,
    .buf_pos = 0,
    .buf_valid = 0
};

static int kreader_fill(void)
{
    ssize_t ret;

    if (!kr.file)
        return -EINVAL;

    /* refill buffer */
    kr.buf_pos = 0;
    ret = kernel_read(kr.file, kr.buf, kr.buf_len, &kr.pos);
    if (ret < 0) {
        pr_err("klex: kernel_read failed: %zd\n", ret);
        kr.buf_valid = 0;
        return (int)ret;
    }
    kr.buf_valid = ret;
    if (kr.buf_valid == 0) {
        eof_flag = 1;
        return 0;
    }
    return 1;
}

/* get one char from the kernel file buffer (returns EOF on end) */
static int kreader_getch(void)
{
    int c;

    if (peekc) {
        c = peekc;
        peekc = 0;
        return c;
    }

    if (kr.buf_pos >= kr.buf_valid) {
        int r = kreader_fill();
        if (r < 0)
            return EOF;
        if (kr.buf_valid == 0)
            return EOF;
    }

    c = (unsigned char)kr.buf[kr.buf_pos++];
    return c;
}

/* peek the next char without consuming (stores in peekc) */
static int spnextchar(void)
{
    if (peekc)
        return peekc;

    if (kr.buf_pos < kr.buf_valid) {
        peekc = (unsigned char)kr.buf[kr.buf_pos];
        return peekc;
    }
    /* refill */
    if (kreader_fill() <= 0)
        return EOF;
    if (kr.buf_valid == 0)
        return EOF;
    peekc = (unsigned char)kr.buf[kr.buf_pos];
    return peekc;
}

/* --- utility: error message in kernel --- */
static void kerror(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    pr_err("klex: line %d: ", line_no);
    vprintk(fmt, ap);
    pr_err("\n");
    va_end(ap);
}

static unsigned int simple_hash(const char *s)
{
    unsigned int sum = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p)
        sum += *p++;
    return sum % (unsigned int)hshsiz;
}

/* findkw: check symbuf against kwtab */
static int findkw(void)
{
    char local[NCPS];
    const char *wp = symbuf;
    if (*wp == '.')
        wp++;
    strlcpy(local, wp, NCPS);
    for (struct kwtab *kp = kwtab; kp->kwname; ++kp) {
        if (strcmp(local, kp->kwname) == 0) {
            cval = kp->kwval;
            return 1;
        }
    }
    return 0;
}

static int lookup(void)
{
    unsigned int ihash = 0;
    struct hshtab *rp;
    char *sp = symbuf;

    if (*sp == '.')
        sp++;

    ihash = simple_hash(sp);
    rp = &hshtab[ihash];

    if (rp->hflag & 0x1) /* some key flag marker from init */
        if (findkw())
            return TOK_KEYW;

    /* linear probe looking for match or empty slot */
    for (size_t i = 0; i < hshsiz; ++i) {
        struct hshtab *cur = &hshtab[(ihash + i) % hshsiz];

        if (cur->name[0] == '\0') {
            /* empty slot: create symbol */
            if (hshused >= hshsiz) {
                kerror("Symbol table overflow");
                return -ENOSPC;
            }
            cur->hclass = 0;
            cur->htype = 0;
            cur->hoffset = 0;
            cur->dimp = 0;
            cur->hflag = 0x2; /* XD flag */
            strlcpy(cur->name, symbuf, NCPS);
            ++hshused;
            cval = (int)(cur - hshtab);
            return TOK_NAME;
        }

        if (strncmp(cur->name, symbuf, NCPS) == 0) {
            cval = (int)(cur - hshtab);
            return TOK_NAME;
        }
    }

    /* unexpected */
    kerror("lookup failure");
    return -EINVAL;
}

static int subseq(int c, int a, int b)
{
    int nc = spnextchar();
    if (nc != c)
        return a;
    /* consume */
    peekc = 0;
    /* skip the char from buffer since spnextchar didn't advance */
    if (kr.buf_pos < kr.buf_valid)
        kr.buf_pos++;
    return b;
}

static int mapch(int terminator)
{
    int a = kreader_getch();
    int mpeek = 0;

    if (a == EOF)
        return -1;

 for_loop:
    if (a == terminator)
        return -1;
    switch (a) {
    case '\n':
    case '\0':
        kerror("Nonterminated string");
        peekc = a;
        return -1;
    case '\\': {
        int nxt = kreader_getch();
        if (nxt == EOF)
            return -1;
        switch (nxt) {
        case 't': return '\t';
        case 'n': return '\n';
        case 'b': return '\b';
        case 'r': return '\r';
        case '0': case '1': case '2': case '3':
        case '4': case '5': case '6': case '7': {
            int n = 0, cnt = 0;
            int ch = nxt;
            while (cnt < 3 && ch >= '0' && ch <= '7') {
                n = (n << 3) + (ch - '0');
                ch = kreader_getch();
                ++cnt;
            }
            /* push last read back */
            peekc = ch;
            return n;
        }
        case '\n':
            if (!inhdr)
                line_no++;
            inhdr = 0;
            a = kreader_getch();
            goto for_loop;
        default:
            return nxt;
        }
    }
    default:
        return a;
    }
}

static int getstr(void)
{
    int c;
    char *sp = savstr;
    nchstr = 1;

    while ((c = mapch('"')) >= 0) {
        nchstr++;
        if ((size_t)(sp - savstr) >= STRSIZ - 1) {
            sp = savstr;
            kerror("String too long");
        } else {
            *sp++ = (char)c;
        }
    }
    *sp = '\0';
    strptr = sp;
    cval = isn++;
    return TOK_STRING;
}

/* getcc: read character constant; store into cval and return TOK_CON */
static int getcc(void)
{
    int c;
    int cc = 0;
    unsigned char *ccp = (unsigned char *)&cval;

    cval = 0;
    while ((c = mapch('\'')) >= 0) {
        if (cc++ < NCPW)
            *ccp++ = (unsigned char)c;
    }
    if (cc > NCPW)
        kerror("Long character constant");
    return TOK_CON;
}

/* symbol: simplified lexer */
static int symbol(void)
{
    int c;

    if (peeksym >= 0) {
        c = peeksym;
        peeksym = -1;
        if (c == TOK_NAME)
            mosflg = 0;
        return c;
    }

    if (peekc) {
        c = peekc;
        peekc = 0;
    } else {
        if (eof_flag)
            return TOK_EOF;
        c = kreader_getch();
        if (c == EOF) {
            eof_flag = 1;
            return TOK_EOF;
        }
    }

loop:
    if (c == '\n') {
        if (!inhdr)
            line_no++;
        inhdr = 0;
        c = kreader_getch();
        goto loop;
    }
    if (isspace(c)) {
        c = kreader_getch();
        goto loop;
    }

    if (c == '/') {
        /* possible comment */
        int nc = spnextchar();
        if (nc == '*') {
            /* consume '*' */
            if (kr.buf_pos < kr.buf_valid)
                kr.buf_pos++;
            for (;;) {
                int ch = kreader_getch();
                if (ch == EOF) {
                    eof_flag = 1;
                    kerror("Nonterminated comment");
                    return 0;
                }
                if (ch == '*') {
                    if (spnextchar() == '/') {
                        /* consume '/' */
                        if (kr.buf_pos < kr.buf_valid)
                            kr.buf_pos++;
                        /* next char */
                        c = kreader_getch();
                        goto loop;
                    }
                }
            }
        }
        /* else return divide token */
        return TOK_DIVIDE;
    }

    if (c == '"') {
        return getstr();
    }


    if (isalpha(c) || c == '.') {
        char *sp = symbuf;
        if (mosflg) {
            *sp++ = '.';
            mosflg = 0;
        }
        while ((ctypes_t)0, (isalpha(c) || isdigit(c))) {
            if ((size_t)(sp - symbuf) < NCPS - 1)
                *sp++ = (char)c;
            c = kreader_getch();
        }
        /* pad the rest */
        *sp = '\0';
        peekc = c;
        return lookup();
    }

    /* + and - handling is abbreviated for brevity */
    if (c == '+')
        return TOK_PLUS;
    if (c == '-')
        return TOK_MINUS;
    if (c == '=')
        return TOK_ASSIGN;
    if (c == '&')
        return TOK_AND;
    if (c == '|')
        return TOK_OR;

    return c;
}

/* --- module parsing driver: simple loop that logs tokens --- */
static int klex_parse_all(void)
{
    int tok;
    int count = 0;

    if (!kr.file) {
        kerror("No input file opened");
        return -EINVAL;
    }

    do {
        tok = symbol();
        if (tok == TOK_EOF)
            break;
        if (debug)
            pr_info("klex: tok=%d, cval=%d, sym=\"%s\"\n", tok, cval, symbuf);
        count++;
    } while (!eof_flag);

    pr_info("klex: parsed %d tokens\n", count);
    return 0;
}

static int __init klex_init(void)
{
    int ret = 0;

    if (!input_path) {
        pr_err("klex: input_path module parameter required\n");
        return -EINVAL;
    }

    kr.buf = kmalloc(kr.buf_len, GFP_KERNEL);
    if (!kr.buf) {
        pr_err("klex: cannot allocate read buffer\n");
        return -ENOMEM;
    }

    kr.file = filp_open(input_path, O_RDONLY, 0);
    if (IS_ERR(kr.file)) {
        ret = PTR_ERR(kr.file);
        pr_err("klex: filp_open(%s) failed: %d\n", input_path, ret);
        kr.file = NULL;
        kfree(kr.buf);
        return ret;
    }

    kr.pos = 0;
    kr.buf_pos = 0;
    kr.buf_valid = 0;

    /* allocate hash table */
    hshtab = kcalloc(hshsiz, sizeof(*hshtab), GFP_KERNEL);
    if (!hshtab) {
        pr_err("klex: hshtab allocation failed\n");
        filp_close(kr.file, NULL);
        kfree(kr.buf);
        return -ENOMEM;
    }

    /* mark keywords in hshtab by a hash of their names */
    for (struct kwtab *kp = kwtab; kp->kwname; ++kp) {
        unsigned int idx = simple_hash(kp->kwname);
        hshtab[idx].hflag = 0x1; /* mark slot as keyword hash */
    }

    pr_info("klex: opened %s, starting lexing\n", input_path);
    klex_parse_all();

    return 0;
}

static void __exit klex_exit(void)
{
    if (kr.file)
        filp_close(kr.file, NULL);
    kfree(kr.buf);
    kfree(hshtab);
    pr_info("klex: module unloaded\n");
}

