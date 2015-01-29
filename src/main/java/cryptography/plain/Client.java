package cryptography.plain;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Plain String UTF-8 communication
 * @author Samuel Schmidt
 * @version 1/29/2015
 */
public class Client {
    private static final Logger logger = LogManager.getLogger(Client.class);
    public static void main(String [] args) throws NoSuchProviderException, NoSuchAlgorithmException {
        if (args.length != 2) {
            System.err.println("Usage: java Client <host name> <port number>");
            System.exit(1);
        }

        String hostName = args[0];
        String str = "Hello World!";
        int portNumber = Integer.parseInt(args[1]);

        // Communication
        try{
            // Sockets
            Socket socket = new Socket(hostName, portNumber);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            out.writeUTF(str);
            logger.trace("sent " + str);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}