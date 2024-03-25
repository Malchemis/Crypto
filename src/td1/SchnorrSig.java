package td1;

import it.unisa.dia.gas.jpbc.Element;

public class SchnorrSig {
    private final Element e;
    private final Element s;

    public SchnorrSig(Element e, Element s){
        this.e = e;
        this.s = s;
    }

    public Element getE(){
        return e;
    }

    public Element getS(){
        return s;
    }

}
