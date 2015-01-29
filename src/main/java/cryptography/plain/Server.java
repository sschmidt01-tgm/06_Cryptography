package cryptography.plain;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Plain String UTF-8 communication
 * @author Samuel Schmidt
 * @version 1/29/2015
 */
public class Server {
    private static final Logger logger = LogManager.getLogger(Server.class);
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        if (args.length != 1) {
            System.err.println("Usage: java Server <port number>");
            System.exit(1);
        }
        int portNumber = Integer.parseInt(args[0]);
        logger.trace("Sever started");

        ServerSocket serverSocket;
        Socket clientSocket;
        DataInputStream in;

        try {
            serverSocket = new ServerSocket(portNumber);
            clientSocket = serverSocket.accept();

            in = new DataInputStream(clientSocket.getInputStream());
            String received2 = in.readUTF();

            logger.trace("received " + received2);
        } catch (Exception e ) {
            e.printStackTrace();
        }
    }
}