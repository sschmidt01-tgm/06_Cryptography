package secure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * Key Exchange done in SecureClient/Server without Socket Communication locally
 *
 * @author Samuel Schmidt
 * @version 1/18/2015
 */
public class Test {
    private static final Logger logger = LogManager.getLogger(SecureClient.class);
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        // generate Public and Private Key
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstanceStrong();

        keyPairGenerator.initialize(1024, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // generates synchronous public key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        // uses public key from client to encrypt synchronous public key
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedData = cipher.doFinal(secretKey.getEncoded());

        // DECRYPTION of AES Key
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        SecretKey aesKey = new SecretKeySpec(cipher.doFinal(encryptedData), "AES");


        logger.trace(secretKey.toString() + " algortihm: " + secretKey.getAlgorithm() + " format: " + secretKey.getFormat() + " enc: " + secretKey.getEncoded());
        logger.trace(aesKey.toString() + " algortihm: " + aesKey.getAlgorithm() + " format: " + aesKey.getFormat() + " enc: " + aesKey.getEncoded() );

        logger.trace(aesKey.equals(secretKey));
        logger.trace(aesKey.getClass().equals(secretKey.getClass()));


        logger.trace("decrypted the following: " + aesKey.getEncoded().toString());

        logger.trace(secretKey.hashCode());
        logger.trace(aesKey.hashCode());

    }
}