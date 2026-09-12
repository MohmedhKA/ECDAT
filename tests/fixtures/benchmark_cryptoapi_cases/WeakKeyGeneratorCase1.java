package benchmark.cryptoapi;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class WeakKeyGeneratorCase1 {
    public SecretKey generate() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        return kg.generateKey();
    }
}
