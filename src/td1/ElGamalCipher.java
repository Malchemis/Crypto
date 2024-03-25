package td1;

import it.unisa.dia.gas.jpbc.Element;


public class ElGamalCipher{
    private final Element u;
    private final Element v;
    private final byte[] encryptedData;

    public ElGamalCipher(Element u, Element v, byte[] encryptedData){
        this.u = u;
        this.v = v;
        this.encryptedData = encryptedData;
    }

    public Element getU(){
        return u;
    }

    public Element getV(){
        return v;
    }

    public byte[] getEncryptedData(){
        return encryptedData;
    }

}
