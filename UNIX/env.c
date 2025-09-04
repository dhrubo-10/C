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

/* section op */