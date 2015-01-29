package cryptpgraphy.secure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;

/**
 * Receives a RSA asymmetric public key from the Client
 * generates a AES symmetric key
 * encrypts the AES symmetric key with the RSA asymmetric public key
 * sends the encrypted data to the Client
 *
 * @author Samuel Schmidt
 * @version 1/18/2015
 */
public class SecureServer {

    private static final Logger logger = LogManager.getLogger(SecureServer.class);

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        if (args.length != 1) {
            System.err.println("Usage: java SecureServer <port number>");
            System.exit(1);
        }

        int portNumber = Integer.parseInt(args[0]);

        logger.trace("Sever started");

        try {
            ServerSocket serverSocket =
                    new ServerSocket(Integer.parseInt(args[0]));
            Socket clientSocket = serverSocket.accept();
            ObjectInputStream in = new ObjectInputStream(
                    clientSocket.getInputStream());

            // receives RSA asymmetric public key from Client
            PublicKey publicKey = (PublicKey) in.readObject();

            // generates AES symmetric key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();

            logger.trace("generated AES symmetric key: " + secretKey.toString());
            logger.trace("received public key: " + publicKey.toString());


            // uses asymmetric public RSA key from client to encrypt symmetric AES key
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedData = cipher.doFinal(secretKey.getEncoded());

            OutputStream outputStream = clientSocket.getOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
            dataOutputStream.writeInt(encryptedData.length);
            dataOutputStream.write(encryptedData, 0, encryptedData.length);
            logger.trace("sent AES symmetric key");

        } catch (Exception e ){
            e.printStackTrace();
        }
    }
}