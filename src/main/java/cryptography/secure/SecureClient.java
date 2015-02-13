package cryptography.secure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetSocketAddress;
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

    private static final Logger logger = LogManager.getLogger(SecureClient.class);

    public static void main(String [] args) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (args.length != 2) {
            System.err.println(
                    "Usage: java SecureClient <host name> <port number>");
            System.exit(1);
        }

        String hostName = args[0];
        int portNumber = Integer.parseInt(args[1]);
        String message = "Just Read the Instructions";

        // generate Public and Private Key
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstanceStrong();

        keyPairGenerator.initialize(2048, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        logger.trace("Public Key: " + publicKey.toString());

        // Communication
        try{
            // Sockets
//            Socket socket = new Socket(hostName, portNumber);
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(hostName, portNumber), 5000);
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
            SecretKey aesKey = new SecretKeySpec(cipher.doFinal(encryptedData), "AES");

            logger.trace("decrypted the following AES symmetric key: " + aesKey.toString());

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

            // send IV
            OutputStream outputStream = socket.getOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
            dataOutputStream.write(iv);
            dataOutputStream.flush();

            // send encrypted message
            dataOutputStream = new DataOutputStream(outputStream);
            dataOutputStream.writeInt(encryptedData.length);
            dataOutputStream.write(encryptedData);
            dataOutputStream.flush();

        } catch (Exception e ){
            e.printStackTrace();
        }
    }
}