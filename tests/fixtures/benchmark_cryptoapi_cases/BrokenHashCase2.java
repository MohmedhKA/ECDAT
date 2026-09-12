package benchmark.cryptoapi;

import java.security.MessageDigest;

public class BrokenHashCase2 {
    public byte[] computeHash(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(input);
    }
}
