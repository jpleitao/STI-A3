package server;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class ServerThread extends Thread{

    private final int MAX_COMMUNICATIONS;

    private int currentNumberCommunications;
    private Server server;
    private Socket clientSocket;
    private Server.ObjectStreamBundle streams;

    public ServerThread(Server server, Socket clientSocket) {
        this.server = server;
        this.clientSocket = clientSocket;
        MAX_COMMUNICATIONS = 2;
        currentNumberCommunications = 0;
    }

    public void run() {

        System.out.println("Going to see if I need to send my public key to the client");
        if (!server.sendPublicKeyToClient(clientSocket)) {
            System.out.println("Could not send public key to client");
            return;
        }

        System.out.println("Going to wait for the client's session key");
        streams = server.receiveSessionKey(clientSocket);

        if (streams == null) {
            System.out.println("Could not receive session key");
            return;
        }

        //Send server's certificate encrypted with session key
        if (!server.sendCertificateToClient(streams.outputStream)) {
            System.out.println("Failed to send certificate to the client");
            return;
        }

        //Receive Client's Certificate and validate it
        if (!server.receiveAndValidateServerCertificate(streams.inputStream)) {
            System.out.println("Could not receive the client's certificate or invalid client certificate");
            return ;
        }

        //Now we are ready to actually start exchanging messages!!!
        while (!this.isInterrupted()) {
            //Try sending a string to the client with the received sessionKey
            String message = "Hello from Server";
            boolean result = sendMessage(message, streams.outputStream);
            System.out.println("[1]Sent message and the result was " + result);
            if (!result)
                this.interrupt();

            String received = readMessage(streams.inputStream);
            System.out.println("[1]Received message " + received);
            if (received == null) {
                this.interrupt();
            }
            System.out.println("KSKSKSK");
        }
    }

    private boolean sendMessage(String message, ObjectOutputStream outputStream) {
        if(!server.sendMessage(message, outputStream))
            return false;
        currentNumberCommunications++;
        if(currentNumberCommunications == MAX_COMMUNICATIONS) {
            streams = server.sendNewKey(streams, clientSocket);
            if (streams == null)
                return false;
        }
        return true;
    }

    private String readMessage(ObjectInputStream inputStream) {
        //Check if we need to change the session key
        String message = server.readMessage(inputStream);

        if (message != null) {
            currentNumberCommunications++;
            if(currentNumberCommunications == MAX_COMMUNICATIONS) {
                System.out.println("Going to send new session key");
                streams = server.sendNewKey(streams, clientSocket);
                if (streams == null)
                    return null;
            }
        }
        return message;
    }


}
