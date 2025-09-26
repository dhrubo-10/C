#include "hr.c"

/*Process a single external definition */
extdef()
{
	register o, elsize;
	int type, sclass;
	register struct hshtab *ds;

	if(((o=symbol())==EOF) || o==SEMI)
		return;
	peeksym = o;
	type = INT;
	sclass = EXTERN;
	xdflg = FNDEL;
	if ((elsize = getkeywords(&sclass, &type)) == -1 && peeksym!=NAME)
		goto syntax;
	if (type==STRUCT)
		blkhed();
	do {
		defsym = 0;
		decl1(EXTERN, type, 0, elsize);
		if ((ds=defsym)==0)
			return;
		funcsym = ds;
		ds->hflag =| FNDEL;
		outcode("BS", SYMDEF, ds->name);
		xdflg = 0;
		if ((ds->type&XTYPE)==FUNC) {
			if ((peeksym=symbol())==LBRACE || peeksym==KEYW) {
				funcblk.type = decref(ds->type);
				cfunc(ds->name);
				return;
			}
		} else 
			cinit(ds);
	} while ((o=symbol())==COMMA);
	if (o==SEMI)
		return;
syntax:
	if (o==RBRACE) {
		error("Too many }'s");
		peeksym = 0;
		return;
	}
	error("External definition syntax");
	errflush(o);
	statement(0);
}

/*Process a function definition.*/
cfunc(cs)
char *cs;
{
	register savdimp;

	savdimp = dimp;
	outcode("BBS", PROG, RLABEL, cs);
	declist(ARG);
	regvar = 5;
	retlab = isn++;
	if ((peeksym = symbol()) != LBRACE)
		error("Compound statement required");
	statement(1);
	outcode("BNB", LABEL, retlab, RETRN);
	dimp = savdimp;
}


cinit(ds)
struct hshtab *ds;
{
	register basetype, nel, ninit;
	int o, width, realwidth;

	nel = 1;
	basetype = ds->type;

	while ((basetype&XTYPE)==ARRAY) {
		if ((nel = dimtab[ds->ssp&0377])==0)
			nel = 1;
		basetype = decref(basetype);
	}

	if (basetype==STRUCT) {
		nel =* realwidth/2;
		width = 2;
	}
	if ((peeksym=symbol())==COMMA || peeksym==SEMI) {
		outcode("BSN",CSPACE,ds->name,(nel*width+ALIGN)&~ALIGN);
		return;
	}
	ninit = 0;
	outcode("BBS", DATA, NLABEL, ds->name);
	if ((o=symbol())==LBRACE) {
		do
			ninit = cinit1(ds, basetype, width, ninit, nel);
		while ((o=symbol())==COMMA);
		if (o!=RBRACE)
			peeksym = o;
	} else {
		peeksym = o;
		ninit = cinit1(ds, basetype, width, 0, nel);
	}

	if (basetype==STRUCT) {
		if (o = 2*ninit % realwidth)
			outcode("BN", SSPACE, realwidth-o);
		ninit = (2*ninit+realwidth-2) / realwidth;
		nel =/ realwidth/2;
	}

	if (ninit<nel)
		outcode("BN", SSPACE, (nel-ninit)*realwidth);
	else if (ninit>nel) {
		if ((ds->type&XTYPE)==ARRAY)
			dimtab[ds->ssp&0377] = ninit;
		nel = ninit;
	}
	/* If it's not an array, only one initializer is allowed. */
	if (ninit>1 && (ds->type&XTYPE)!=ARRAY)
		error("Too many initializers");
	if (((nel&width)&ALIGN))
		outcode("B", EVEN);
}