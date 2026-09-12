package benchmark.cryptoapi;

import java.security.MessageDigest;

public class SecureHashCase1 {
    public byte[] computeHash(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input);
    }
}
