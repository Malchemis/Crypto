package td2;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import td1.AESCrypto;
import td1.PairKeys;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * This class is used to implement the Identity-Based Encryption (IBE) scheme.
 */
public class BasicIdentity {

    public BasicIdentity(){}

    public SetUpParameters setup(Pairing pairing){
        Element p = pairing.getG1().newRandomElement().getImmutable();  // P: generator of G1
        Element s = pairing.getZr().newRandomElement().getImmutable();  // s: master secret key
        Element publicKey = p.duplicate().mulZn(s).getImmutable();      // s*P
        return new SetUpParameters(p, s, publicKey);
    }

    public PairKeys keygen(Pairing pairing, String identity, Element s){
        byte[] identityBytes = identity.getBytes();

        // H1(ID)
        Element Q_id = pairing.getG1().newElementFromHash(identityBytes, 0, identityBytes.length).getImmutable();
        // s*Q_id
        Element sk = Q_id.duplicate().mulZn(s).getImmutable();

        return new PairKeys(Q_id, sk);
    }


    public byte[] xor(byte[] a, byte[] b){
        byte[] result = new byte[a.length];
        for(int i = 0; i < a.length; i++){
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    /**
     * Encrypts a message using the Identity-Based Encryption (IBE) scheme with AES.
     */
    public BasicIdentityCipher encrypt(Pairing pairing, Element p, Element publicKey, String identity, byte[] message) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // Compute Q_id = H1(ID)
        byte[] identityBytes = identity.getBytes();
        Element Q_id = pairing.getG1().newElementFromHash(identityBytes, 0, identityBytes.length).getImmutable();
        // Get a random element r in Zp
        Element r = pairing.getZr().newRandomElement().getImmutable();
        // Compute U = r*P
        Element U = p.duplicate().mulZn(r).getImmutable();
        // Compute V = M xor H2(e(Q_id, publicKey)^r)
        // pair(e(Q_id, publicKey), P)
        Element e = pairing.pairing(Q_id, publicKey).getImmutable();

        // Generate a random AES key in GT
        Element aesKey = pairing.getGT().newRandomElement().getImmutable();
        // e(Q_id, publicKey)^r
        byte[] V = xor(aesKey.toBytes(), e.powZn(r).toBytes());

        // Encrypt the message using the AES key
        byte[] encryptedData = AESCrypto.encrypt(message, aesKey.toBytes());
        return new BasicIdentityCipher(U, V, encryptedData);
    }

    /**
     * Decrypts a message using the Identity-Based Encryption (IBE) scheme with AES.
     */
    public byte[] decrypt(Pairing pairing, Element s, BasicIdentityCipher cipher) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // Compute e(d_id, U) where d_id = s*Q_id, U = r*P
        Element e = pairing.pairing(s, cipher.getU()).getImmutable();
        // Get back AES key : V XOR H2(e(Q_id, publicKey)^r)
        byte[] aesKey = xor(cipher.getV(), e.toBytes());
        // Decrypt the message using the AES key
        return AESCrypto.decrypt(cipher.getEncryptedData(), aesKey);
    }


    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String curveParamsPath = "D:/IntelliJ/workspace/Lib/params/curves/a.properties";
        String identity = "alice";
        String message = "Hello World!";
        byte[] messageBytes = message.getBytes();

        BasicIdentity basicIdentity = new BasicIdentity();
        Pairing pairing = PairingFactory.getPairing(curveParamsPath);
        SetUpParameters setUpParameters = basicIdentity.setup(pairing);
        PairKeys pairKeys = basicIdentity.keygen(pairing, identity, setUpParameters.getS());

        BasicIdentityCipher cipher = basicIdentity.encrypt(pairing, setUpParameters.getP(), setUpParameters.getPublicKey(), identity, messageBytes);
        byte[] decryptedMessage = basicIdentity.decrypt(pairing, pairKeys.getPrivateKey(), cipher);

        System.out.println("Original message: " + message);
        System.out.println("Encrypted message: " + new String(cipher.getEncryptedData()));
        System.out.println("Decrypted message: " + new String(decryptedMessage));
    }
}
