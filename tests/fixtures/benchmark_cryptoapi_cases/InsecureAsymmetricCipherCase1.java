package benchmark.cryptoapi;

import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.KeyPair;

public class InsecureAsymmetricCipherCase1 {
    public void go() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = kpg.generateKeyPair();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
    }
}
