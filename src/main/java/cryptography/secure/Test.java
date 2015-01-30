package cryptography.secure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;

/**
 * Key Exchange done in SecureClient/Server without Socket Communication locally
 *
 * @author Samuel Schmidt
 * @version 1/18/2015
 */
public class Test {

    private static final Logger logger = LogManager.getLogger(Test.class);

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {

        String message = "Just Read the Instructions";

        // generate Public and Private Key
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstanceStrong();

        keyPairGenerator.initialize(2048, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // generates synchronous public key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();

        // uses public key from client to encrypt synchronous public key
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedData = cipher.doFinal(secretKey.getEncoded());

        // DECRYPTION of AES Key
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        SecretKey aesKey = new SecretKeySpec(cipher.doFinal(encryptedData), "AES");


        logger.info(secretKey.toString() + " algortihm: " + secretKey.getAlgorithm() + " format: " + secretKey.getFormat() + " enc: " + secretKey.getEncoded());
        logger.info(aesKey.toString() + " algortihm: " + aesKey.getAlgorithm() + " format: " + aesKey.getFormat() + " enc: " + aesKey.getEncoded());

        logger.info("" + aesKey.equals(secretKey));
        logger.info("" + aesKey.getClass().equals(secretKey.getClass()));


        logger.info("decrypted the following: " + new String(aesKey.getEncoded()));

        logger.info("" + secretKey.hashCode());
        logger.info("" + aesKey.hashCode());


        // use the AES key for encrypting a message
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParameterSpec);
        encryptedData = cipher.doFinal(message.getBytes("UTF-8"));
        String encrypted = new String(encryptedData);
        logger.info("encrypted aes message: " + encrypted);

        // use AES key for decrypting a message
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey,ivParameterSpec);
        String decrypted = new String(cipher.doFinal(encryptedData), "UTF-8");
        logger.info("decrypted aes message: " + decrypted );
    }
}