package td1;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

/**
 * This class implements the El-Gamal encryption scheme with elliptic curves and AES.
 */
public class ElGamal {
    private final PairKeys pairKeys;
    private final Pairing p;

    public ElGamal(Pairing p, Element g) {
        this.p = p;
        // Generate public and private keys
        Element privateKey = p.getZr().newRandomElement();
        Element publicKey = g.duplicate().mulZn(privateKey);
        this.pairKeys = new PairKeys(publicKey, privateKey);
    }

    public ElGamalCipher encrypt(byte[] data, Element g, Element publicKey) {
        try {
            Element a = p.getZr().newRandomElement();
            Element u = g.duplicate().mulZn(a);             // u = g^a

            // get symmetric key for AES
            Element k = p.getG1().newRandomElement();
            Element v = publicKey.duplicate().mulZn(a);     // v = h^a
            v.add(k);                                       // combine with AES key

            // Encrypt the data
            byte[] encrypted = AESCrypto.encrypt(data, k.toBytes());
            return new ElGamalCipher(u, v, encrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decrypt(ElGamalCipher cipher) {
        try {
            // Compute w = u^b
            Element w = cipher.getU().duplicate().mulZn(pairKeys.getPrivateKey());
            // Compute k = v/w
            Element k = cipher.getV().duplicate().sub(w);
            // Decrypt the data
            return AESCrypto.decrypt(cipher.getEncryptedData(), k.toBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public PairKeys getPairKeys() {
        return pairKeys;
    }

}
