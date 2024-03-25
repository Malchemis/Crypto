package td2;

import it.unisa.dia.gas.jpbc.Element;

public class BasicIdentityCipher {
    private final Element u;
    private final byte[] v;
    private final byte[] encryptedData;
    public BasicIdentityCipher(Element u, byte[] v, byte[] encryptedData) {
        this.u = u;
        this.v = v;
        this.encryptedData = encryptedData;
    }

    public Element getU() {
        return u;
    }

    public byte[] getV() {
        return v;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }
}
