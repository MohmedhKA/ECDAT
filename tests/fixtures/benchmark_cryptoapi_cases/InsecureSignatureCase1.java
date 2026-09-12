package benchmark.cryptoapi;

import java.security.Signature;
import java.security.KeyPairGenerator;
import java.security.KeyPair;

public class InsecureSignatureCase1 {
    public void sign(byte[] data) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = kpg.generateKeyPair();
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(kp.getPrivate());
        sig.update(data);
        sig.sign();
    }
}
