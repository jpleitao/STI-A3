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
        MAX_COMMUNICATIONS = 1;
        currentNumberCommunications = 0;
    }

    public void run() {

        //Send public key to the client
        System.out.println("Going to send the server's public key to the client");
        if (!server.sendPublicKeyToClient(clientSocket)) {
            System.out.println("Failed to send public key to client!");
            return ;
        }

        //Receive session key
        System.out.println("Going to wait for the client's session key");
        streams = server.receiveSessionKey(clientSocket);

        if (streams == null) {
            System.out.println("Could not receive session key");
             return ;
        }

        //Authenticate the user and send him feedback
        if (!server.handleUserAuthentication(streams)) {
            System.out.println("User authentication failed!");
            return ;
        }

        //Now we are ready to actually start exchanging messages!!!
        //FIXME THIS PART IS BUGGY
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
            this.interrupt();
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
            currentNumberCommunications = 0;
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
                currentNumberCommunications = 0;
            }
        }
        return message;
    }


}
