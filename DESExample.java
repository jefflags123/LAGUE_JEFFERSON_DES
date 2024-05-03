import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class DESExample {

    public static void main(String[] args) {
        try {
            // Step 1: Generate DES Key
            SecretKey secretKey = generateDESKey();

            // Step 2: Create Cipher Instance
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

            // Step 3: Convert String to Byte[] Array
            String plaintext = "Hello, DES!";
            byte[] plaintextBytes = plaintext.getBytes();

            // Step 4: Encryption
            byte[] encryptedBytes = encrypt(plaintextBytes, secretKey, cipher);
            System.out.println("Encrypted: " + new String(encryptedBytes));

            // Step 5: Decryption
            byte[] decryptedBytes = decrypt(encryptedBytes, secretKey, cipher);
            System.out.println("Decrypted: " + new String(decryptedBytes));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKey generateDESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        return keyGenerator.generateKey();
    }

    private static byte[] encrypt(byte[] plaintext, SecretKey secretKey, Cipher cipher) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext);
    }

    private static byte[] decrypt(byte[] ciphertext, SecretKey secretKey, Cipher cipher) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(ciphertext);
    }
}
    