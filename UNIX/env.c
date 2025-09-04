#include "hr.c"

int	isn	1;
int	stflg	1;
int	peeksym	-1;
int	line	1;
int	debug	0;
int	dimp	0;
struct	tname	funcblk { NAME, 0, 0, REG, 0, 0 };
int	*treespace { osspace };

struct kwtab {
	char	*kwname;
	int	kwval;
} kwtab[]
{
	"int",		INT,
	"char",		CHAR,
	"float",	FLOAT,
	"double",	DOUBLE,
	"struct",	STRUCT,
	"long",		LONG,
	"auto",		AUTO,
	"extern",	EXTERN,
	"static",	STATIC,
	"register",	REG,
	"goto",		GOTO,
	"return",	RETURN,
	"if",		IF,
	"while",	WHILE,
	"else",		ELSE,
	"switch",	SWITCH,
	"case",		CASE,
	"break",	BREAK,
	"continue",	CONTIN,
	"do",		DO,
	"default",	DEFAULT,
	"for",		FOR,
	"sizeof",	SIZEOF,
	0,		0,
};

main(argc, argv)
char *argv[];
{
	extern fin;
	register char *sp;
	register i;
	register struct kwtab *ip;

	if(argc<3) {
		error("Arg count");
		exit(1);
	}
	if((fin=open(argv[1],0))<0) {
		error("Can't find %s", argv[1]);
		exit(1);
	}
	if (fcreat(argv[2], obuf)<0 || fcreat(argv[3], sbuf)<0) {
		error("Can't create temp");
		exit(1);
	}
	if (argc>4)
		proflg++;

	for (ip=kwtab; (sp = ip->kwname); ip++) {
		i = 0;
		while (*sp)
			i =+ *sp++;
		hshtab[i%hshsiz].hflag = FKEYW;
	}
	while(!eof) {
		extdef();
		blkend();
	}
	outcode("B", EOF);
	strflg++;
	outcode("B", EOF);
	fflush(obuf);
	fflush(sbuf);
	exit(nerror!=0);
}


lookup()
{
	int ihash;
	register struct hshtab *rp;
	register char *sp, *np;

	ihash = 0;
	sp = symbuf;
	if (*sp=='.')
		sp++;
	while (sp<symbuf+ncps)
		ihash =+ *sp++;
	rp = &hshtab[ihash%hshsiz];
	if (rp->hflag&FKEYW)
		if (findkw())
			return(KEYW);
	while (*(np = rp->name)) {
		for (sp=symbuf; sp<symbuf+ncps;)
			if (*np++ != *sp++)
				goto no;
		csym = rp;
		return(NAME);
	no:
		if (++rp >= &hshtab[hshsiz])
			rp = hshtab;
	}
	if(++hshused >= hshsiz) {
		error("Symbol table overflow");
		exit(1);
	}
	rp->hclass = 0;
	rp->htype = 0;
	rp->hoffset = 0;
	rp->dimp = 0;
	rp->hflag =| xdflg;
	sp = symbuf;
	for (np=rp->name; sp<symbuf+ncps;)
		*np++ = *sp++;
	csym = rp;
	return(NAME);
}


findkw()
{
	register struct kwtab *kp;
	register char *p1, *p2;
	char *wp;

	wp = symbuf;
	if (*wp=='.')
		wp++;
	for (kp=kwtab; (p2 = kp->kwname); kp++) {
		p1 = wp;
		while (*p1 == *p2++)
			if (*p1++ == '\0') {
				cval = kp->kwval;
				return(1);
			}
	}
	return(0);
}


symbol() {
	register c;
	register char *sp;

	if (peeksym>=0) {
		c = peeksym;
		peeksym = -1;
		if (c==NAME)
			mosflg = 0;
		return(c);
	}
	if (peekc) {
		c = peekc;
		peekc = 0;
	} else
		if (eof)
			return(EOF);
		else
			c = getchar();
loop:
	switch(ctab[c]) {

	case INSERT:		/* ignore newlines */
		inhdr = 1;
		c = getchar();
		goto loop;

	case NEWLN:
		if (!inhdr)
			line++;
		inhdr = 0;

	case SPACE:
		c = getchar();
		goto loop;

	case EOF:
		eof++;
		return(0);

	case PLUS:
		return(subseq(c,PLUS,INCBEF));

	case MINUS:
		return(subseq(c,subseq('>',MINUS,ARROW),DECBEF));

	case ASSIGN:
		if (subseq(' ',0,1)) return(ASSIGN);
		c = symbol();
		if (c>=PLUS && c<=EXOR) {
			if (spnextchar() != ' '
			 && (c==MINUS || c==AND || c==TIMES)) {
				error("Warning: assignment operator assumed");
				nerror--;
			}
			return(c+ASPLUS-PLUS);
		}
		if (c==ASSIGN)
			return(EQUAL);
		peeksym = c;
		return(ASSIGN);

	case LESS:
		if (subseq(c,0,1)) return(LSHIFT);
		return(subseq('=',LESS,LESSEQ));

	case GREAT:
		if (subseq(c,0,1)) return(RSHIFT);
		return(subseq('=',GREAT,GREATEQ));

	case EXCLA:
		return(subseq('=',EXCLA,NEQUAL));

	case DIVIDE:
		if (subseq('*',1,0))
			return(DIVIDE);
		while ((c = spnextchar()) != EOF) {
			peekc = 0;
			if (c=='*') {
				if (spnextchar() == '/') {
					peekc = 0;
					c = getchar();
					goto loop;
				}
			}
		}
		eof++;
			error("Nonterminated comment");
			return(0);

	case PERIOD:
	case DIGIT:
		peekc = c;
		if ((c=getnum(c=='0'?8:10)) == FCON)
			cval = isn++;
		return(c);

	case DQUOTE:
		return(getstr());

	case SQUOTE:
		return(getcc());

	case LETTER:
		sp = symbuf;
		if (mosflg) {
			*sp++ = '.';
			mosflg = 0;
		}
		while(ctab[c]==LETTER || ctab[c]==DIGIT) {
			if (sp<symbuf+ncps) *sp++ = c;
			c = getchar();
		}
		while(sp<symbuf+ncps)
			*sp++ = '\0';
		peekc = c;
		if ((c=lookup())==KEYW && cval==SIZEOF)
			c = SIZEOF;
		return(c);

	case AND:
		return(subseq('&', AND, LOGAND));

	case OR:
		return(subseq('|', OR, LOGOR));

	case UNKN:
		error("Unknown character");
		c = getchar();
		goto loop;

	}
	return(ctab[c]);
}
/* section op */