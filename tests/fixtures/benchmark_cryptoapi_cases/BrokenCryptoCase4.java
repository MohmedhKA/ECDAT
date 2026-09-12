package benchmark.cryptoapi;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BrokenCryptoCase4 {
    public void go(byte[] raw) throws Exception {
        SecretKey key = new SecretKeySpec(raw, "RC4");
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    }
}
