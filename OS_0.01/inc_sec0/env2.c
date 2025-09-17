#include "hr.c"

build(op) {
	register int t1;
	int t2, t3, t;
	struct tnode *p3, *disarray();
	register struct tnode *p1, *p2;
	int d, dope, leftc, cvn, pcvn;


	if (op==LBRACK) {
		build(PLUS);
		op = STAR;
	}
	dope = opdope[op];
	if ((dope&BINARY)!=0) {
		p2 = chkfun(disarray(*--cp));
		t2 = p2->type;
	}
	p1 = *--cp;

	if (op==SIZEOF) {
		t1 = length(p1);
		p1->op = CON;
		p1->type = INT;
		p1->dimp = 0;
		p1->value = t1;
		*cp++ = p1;
		return;
	}
	if (op!=AMPER) {
		p1 = disarray(p1);
		if (op!=CALL)
			p1 = chkfun(p1);
	}
	t1 = p1->type;
	pcvn = 0;
	t = INT;
	switch (op) {

	/* end of expression */
	case 0:
		*cp++ = p1;
		return;

	/* no-conversion operators */
	case QUEST:
		if (p2->op!=COLON)
			error("Illegal conditional");
		t = t2;

	case COMMA:
	case LOGAND:
	case LOGOR:
		*cp++ = block(2, op, t, 0, p1, p2);
		return;

	case CALL:
		if ((t1&XTYPE) != FUNC)
			error("Call of non-function");
		*cp++ = block(2,CALL,decref(t1),p1->dimp,p1,p2);
		return;

	case STAR:
		if (p1->op==AMPER ) {
			*cp++ = p1->tr1;
			return;
		}
		if ((t1&XTYPE) == FUNC)
			error("Illegal indirection");
		*cp++ = block(1,STAR,decref(t1),p1->dimp,p1);
		return;

	case AMPER:
		if (p1->op==STAR) {
			p1->tr1->dimp = p1->dimp;
			p1->tr1->type = incref(t1);
			*cp++ = p1->tr1;
			return;
		}
		if (p1->op==NAME) {
			*cp++ = block(1,op,incref(t1),p1->dimp,p1);
			return;
		}
		error("Illegal lvalue");
		break;

	/* a->b goes to (*a).b*/
	case ARROW:
		*cp++ = p1;
		chkw(p1, -1);
		p1->type = PTR+STRUCT;
		build(STAR);
		p1 = *--cp;


	case DOT:
		if (p2->op!=NAME || (p2->class!=MOS && p2->class!=FMOS))
			error("Illegal structure ref");
		*cp++ = p1;
		t = t2;
		if ((t&XTYPE) == ARRAY) {
			t = decref(t);
			p2->ssp++;
		}
		setype(p1, t, p2->dimp);
		build(AMPER);
		*cp++ = block(1,CON,NOTYPE,0,p2->nloc);
		build(PLUS);
		if ((t2&XTYPE) != ARRAY)
			build(STAR);
		if (p2->class == FMOS)
			*cp++ = block(2, FSEL, t, 0, *--cp, p2->dimp);
		return;
	}
	if ((dope&LVALUE)!=0)
		chklval(p1);
	if ((dope&LWORD)!=0)
		chkw(p1, LONG);
	if ((dope&RWORD)!=0)
		chkw(p2, LONG);
	if ((dope&BINARY)==0) {
		if (op==ITOF)
			t1 = DOUBLE;
		else if (op==FTOI)
			t1 = INT;
		if (!fold(op, p1, 0))
			*cp++ = block(1,op,t1,p1->dimp,p1);
		return;
	}
	cvn = 0;
	if (t1==STRUCT || t2==STRUCT) {
		error("Unimplemented structure operation");
		t1 = t2 = INT;
	}
	if (t2==NOTYPE) {
		t = t1;
		p2->type = INT;	/* no int cv for struct */
		t2 = INT;
	} else
		cvn = cvtab[lintyp(t1)][lintyp(t2)];
	leftc = (cvn>>4)&017;
	cvn =& 017;
	t = leftc? t2:t1;
	if (dope&ASSGOP) {
		t = t1;
		if (op==ASSIGN && (cvn==ITP||cvn==PTI))
			cvn = leftc = 0;
		if (leftc)
			cvn = leftc;
		leftc = 0;
	} else if (op==COLON && t1>=PTR && t1==t2)
		cvn = 0;
	else if (dope&RELAT) {
		if (op>=LESSEQ && (t1>=PTR || t2>=PTR))
			op =+ LESSEQP-LESSEQ;
		if (cvn==PTI)
			cvn = 0;
	}
	if (cvn==PTI) {
		cvn = 0;
		if (op==MINUS) {
			t = INT;
			pcvn++;
		} else {
			if (t1!=t2 || t1!=(PTR+CHAR))
				cvn = XX;
		}
	}
	if (cvn) {
		t1 = plength(p1);
		t2 = plength(p2);
		if (cvn==XX || (cvn==PTI&&t1!=t2))
			error("Illegal conversion");
		else if (leftc)
			p1 = convert(p1, t, cvn, t2);
		else
			p2 = convert(p2, t, cvn, t1);
	}
	if (dope&RELAT)
		t = INT;
	if (fold(op, p1, p2)==0)
		*cp++ = block(2,op,t,(p1->dimp==0? p2:p1)->dimp,p1,p2);
	if (pcvn && t1!=(PTR+CHAR)) {
		p1 = *--cp;
		*cp++ = convert(p1, 0, PTI, plength(p1->tr1));
	}
}