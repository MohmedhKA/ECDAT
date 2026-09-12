package benchmark.cryptoapi;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;

public class PredictableCryptographicKeyCase1 {
    public void encryptData(byte[] data) throws Exception {
        String defaultKey = "defaultsecretkey";
        byte[] keyBytes = defaultKey.substring(0, 8).getBytes("UTF-8");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        cipher.doFinal(data);
    }
}
