package walletkeyencryption;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Scanner;

public class WalletKeyEncryption {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 16;
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 256;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("=== Wallet Key Encryption ===");
        System.out.println("1. Encrypt Wallet Private Key");
        System.out.println("2. Decrypt Wallet Private Key");
        System.out.print("Choose an option (1 or 2): ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        switch (choice) {
            case 1:
                System.out.print("Enter the private key to encrypt: ");
                String privateKey = scanner.nextLine();
                System.out.print("Enter a password: ");
                String password = scanner.nextLine();
                try {
                    String encryptedKey = encryptPrivateKey(privateKey, password);
                    System.out.println("Encrypted Key: " + encryptedKey);
                } catch (Exception e) {
                    System.out.println("Error during encryption: " + e.getMessage());
                }
                break;

            case 2:
                System.out.print("Enter the encrypted private key: ");
                String encryptedKey = scanner.nextLine();
                System.out.print("Enter the password: ");
                password = scanner.nextLine();
                try {
                    String decryptedKey = decryptPrivateKey(encryptedKey, password);
                    System.out.println("Decrypted Key: " + decryptedKey);
                } catch (Exception e) {
                    System.out.println("Error during decryption: " + e.getMessage());
                }
                break;

            default:
                System.out.println("Invalid choice! Please choose 1 or 2.");
        }

        scanner.close();
    }

    private static String encryptPrivateKey(String privateKey, String password) throws Exception {
        // Generate a random salt and IV
        byte[] salt = generateRandomBytes(SALT_LENGTH);
        byte[] iv = generateRandomBytes(IV_LENGTH);

        // Derive a key from the password
        SecretKey secretKey = deriveKey(password, salt);

        // Encrypt the private key
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] encryptedData = cipher.doFinal(privateKey.getBytes());

        // Combine salt, IV, and encrypted data into one Base64 string
        return Base64.getEncoder().encodeToString(salt) + ":" +
               Base64.getEncoder().encodeToString(iv) + ":" +
               Base64.getEncoder().encodeToString(encryptedData);
    }

    private static String decryptPrivateKey(String encryptedPrivateKey, String password) throws Exception {
        // Split the input string into salt, IV, and encrypted data
        String[] parts = encryptedPrivateKey.split(":");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid encrypted private key format.");
        }

        byte[] salt = Base64.getDecoder().decode(parts[0]);
        byte[] iv = Base64.getDecoder().decode(parts[1]);
        byte[] encryptedData = Base64.getDecoder().decode(parts[2]);

        // Derive the key from the password and salt
        SecretKey secretKey = deriveKey(password, salt);

        // Decrypt the private key
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] decryptedData = cipher.doFinal(encryptedData);

        return new String(decryptedData);
    }

    private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] generateRandomBytes(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
