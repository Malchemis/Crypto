package td1;

import it.unisa.dia.gas.jpbc.Element;

/**
 * This class is used to store the keys used for encryption and decryption.
 * In particular, for El-Gamal/Elliptic Curve encryption, the keys are the public and private keys.
 */
public class PairKeys {
    private final Element publicKey;
    private final Element privateKey;

    public PairKeys(Element publicKey, Element privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public Element getPublicKey() {
        return publicKey;
    }

    public Element getPrivateKey() {
        return privateKey;
    }
}
