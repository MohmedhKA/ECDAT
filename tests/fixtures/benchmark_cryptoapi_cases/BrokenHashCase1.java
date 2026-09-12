package benchmark.cryptoapi;

import java.security.MessageDigest;

public class BrokenHashCase1 {
    public byte[] computeHash(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(input);
    }
}
