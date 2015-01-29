package cryptpgraphy.secure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;

/**
 * Creates a Public/Private Keypair using RSA
 * transmits the RSA asymmetric public key to the Server
 * receives data (AES symmetric key) which is encrypted with the RSA asymmetric public key
 * decrypts the data using the RSA asymmetric private key
 * has access to AES symmetric key, which was generated on the server
 *
 * @author Samuel Schmidt
 * @version 1/18/2015
 */
public class SecureClient {
    private static final Logger logger = LogManager.getLogger();
    public static void main(String [] args) throws NoSuchProviderException, NoSuchAlgorithmException {
        if (args.length != 2) {
            System.err.println(
                    "Usage: java SecureClient <host name> <port number>");
            System.exit(1);
        }

        String hostName = args[0];
        int portNumber = Integer.parseInt(args[1]);

        // generate Public and Private Key
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstanceStrong();

        keyPairGenerator.initialize(1024, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        logger.trace("Public Key: " + publicKey.toString());

        // Communication
        try{
            // Sockets
            Socket socket = new Socket(hostName, portNumber);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(
                    socket.getOutputStream());
            objectOutputStream.writeObject(publicKey);
            objectOutputStream.flush();

            logger.trace("sent public key");

            InputStream in = socket.getInputStream();
            DataInputStream dis = new DataInputStream(in);

            int len = dis.readInt();
            byte[] encryptedData = new byte[len];
            if (len > 0) {
                dis.readFully(encryptedData);
            }

            logger.trace("received encrypted data");

            // DECRYPTION of AES Key
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            SecretKey aesKey = null;
            aesKey = new SecretKeySpec(cipher.doFinal(encryptedData), "AES");

            logger.trace("decrypted the following AES symmetric key: " + aesKey.toString());

        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }
}