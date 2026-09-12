package benchmark.cryptoapi;

import java.security.MessageDigest;

public class BrokenHashCase3 {
    public byte[] computeHash(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD2");
        return md.digest(input);
    }
}
