package td2;

import it.unisa.dia.gas.jpbc.Element;

/**
 * This class is used to store the public parameters used for the Identity-Based Encryption (IBE) scheme.
 */
public class SetUpParameters {
    private final Element p;            // P: generator of G1
    private final Element s;            // s: master secret key
    private final Element publicKey;    // s*P

    public SetUpParameters(Element p, Element s, Element publicKey){
        this.p = p;
        this.s = s;
        this.publicKey = publicKey;
    }

    public Element getP(){
        return p;
    }

    public Element getS(){
        return s;
    }

    public Element getPublicKey(){
        return publicKey;
    }
}
