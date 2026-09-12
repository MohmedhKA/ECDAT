package benchmark.cryptoapi;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class BrokenCryptoCase3 {
    public void go() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
        SecretKey key = keyGen.generateKey();
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    }
}
