package td1;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.FileInputStream;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class TestAes {

    private final String secret_file_path = "src/td1/secret.txt";
    private final String file_to_encrypt_path = "src/td1/file_to_encrypt.txt";


    public void test_AES_Only(){
        try {
            TestAes testAes = new TestAes();

            // Read the secret key from the file
            Scanner scanner = new Scanner(new FileInputStream(testAes.secret_file_path));
            String secret = scanner.nextLine();
            scanner.close();

            // Read the file to encrypt
            scanner = new Scanner(new FileInputStream(testAes.file_to_encrypt_path));
            String data = scanner.nextLine();
            scanner.close();

            // Encrypt the data
            byte[] encrypted = AESCrypto.encrypt(data.getBytes(StandardCharsets.UTF_8), secret.getBytes(StandardCharsets.UTF_8));
            // Decrypt the data
            byte[] decrypted = AESCrypto.decrypt(encrypted, secret.getBytes(StandardCharsets.UTF_8));
            System.out.println("Encrypted: " + new String(encrypted));
            System.out.println("Decrypted: " + new String(decrypted));
        } catch (IOException ex) {
            Logger.getLogger(TestAes.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public void test_ElGamal_AES(){
        String curveParamsPath = "D:/IntelliJ/workspace/Lib/params/curves/a.properties";
        Pairing p = PairingFactory.getPairing(curveParamsPath);
        Element g = p.getG1().newRandomElement();

        // Alice & Bob
        ElGamal elGamalAlice = new ElGamal(p, g);
        ElGamal elGamalBob = new ElGamal(p, g);

        // Alice writes a message to Bob
        String m = "Hello Bob!";
        ElGamalCipher cipher = elGamalAlice.encrypt(m.getBytes(StandardCharsets.UTF_8), g, elGamalBob.getPairKeys().getPublicKey());

        // Bob reads the message
        byte[] decrypted = elGamalBob.decrypt(cipher);
        System.out.println("Encrypted: " + new String(cipher.getEncryptedData()));
        System.out.println("Decrypted: " + new String(decrypted));
    }

    public void test_Schnorr() {
        try {
            // Set up the elliptic curve
            String curveParamsPath = "D:/IntelliJ/workspace/Lib/params/curves/a.properties";
            Pairing p = PairingFactory.getPairing(curveParamsPath);
            Element g = p.getG1().newRandomElement();

            // Get private key x and public key y=g^x
            ElGamal elGamalAlice = new ElGamal(p, g);
            Element x = elGamalAlice.getPairKeys().getPrivateKey();
            Element y = elGamalAlice.getPairKeys().getPublicKey();

            // Get r = g^k
            Element k = p.getZr().newRandomElement();
            Element r = g.duplicate().mulZn(k);

            // Generate a Schnorr signature using SHA-256
            String message = "Hello I'm a super message!";
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(message.getBytes());
            md.update(r.toBytes());

            // Get e and s (H(r, m) and k - xe)
            Element e = p.getZr().newElementFromHash(md.digest(), 0, md.getDigestLength());
            Element s = k.duplicate().sub(x.duplicate().mulZn(e));
            SchnorrSig sig = new SchnorrSig(e, s);  // Publish

            // Verify
            String message2 = "Hello I'm a super message!";
            // compute r_v = g^s * y^e
            Element r_v = g.duplicate().mulZn(sig.getS()).add(y.duplicate().mulZn(sig.getE()));

            // compute e_v = H(r_v, m)
            MessageDigest md_v = MessageDigest.getInstance("SHA-256");
            md_v.update(message2.getBytes());
            md_v.update(r_v.toBytes());
            Element e_v = p.getZr().newElementFromHash(md_v.digest(), 0, md_v.getDigestLength());

            System.out.println("Message: " + message);
            System.out.println("Signature: " + e + ", " + s);
            System.out.println("Signature is valid: " + e.isEqual(e_v));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        System.out.println("---------------------------------- TD1 ----------------------------------\n");
        TestAes testAes = new TestAes();
        System.out.println("----------------- Testing AES only -----------------");
        testAes.test_AES_Only();
        System.out.println("\n----------------- Testing ElGamal with AES -----------------");
        testAes.test_ElGamal_AES();
        System.out.println("\n----------------- Testing Schnorr Signature -----------------");
        testAes.test_Schnorr();
    }
}
