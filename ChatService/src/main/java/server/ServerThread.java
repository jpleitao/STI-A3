package server;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class ServerThread extends Thread{

    private final int MAX_COMMUNICATIONS;

    private int currentNumberCommunications;
    private String username;
    private Server server;
    private Socket clientSocket;
    private Server.ObjectStreamBundle streams;

    public ServerThread(Server server, Socket clientSocket) {
        this.server = server;
        this.clientSocket = clientSocket;
        MAX_COMMUNICATIONS = 5;
        currentNumberCommunications = 1;
    }

    public void run() {

        //Send public key to the client
        //System.out.println("Going to send the server's public key to the client");
        if (!server.sendPublicKeyToClient(clientSocket)) {
            System.out.println("Failed to send public key to client!");
            return ;
        }

        //Receive session key
        //System.out.println("Going to wait for the client's session key");
        streams = server.receiveSessionKey(clientSocket);

        if (streams == null) {
            //System.out.println("Could not receive session key");
             return ;
        }

        //Authenticate the user and send him feedback
        username = server.handleUserAuthentication(streams);
        if(username == null){
            //System.out.println("User authentication failed!");
            return ;
        }
        sendMessage(username + " just logged in. Send him/her a big welcome! :)", streams.outputStream);

        //Now we are ready to actually start exchanging messages!!!
        while (!this.isInterrupted()) {
            String message = readMessage(streams.inputStream);
            if (message != null) {
                if(message.equals(".quit")){
                    disconnect();
                }
                else if(!message.equals("")){
                    //System.out.println("Received " + message + " from client");
                    sendMessage(username + " says...\t" + message, streams.outputStream);
                }
            }
            else
                disconnect();
        }

    }

    private boolean sendMessage(String message, ObjectOutputStream outputStream) {
        return (!server.sendMessage(message, outputStream));
    }

    private String readMessage(ObjectInputStream inputStream) {
        //Check if we need to change the session key
        String message = server.readMessage(inputStream);
        if (message != null && !message.equals(".quit")) {
            currentNumberCommunications++;
            if(currentNumberCommunications == MAX_COMMUNICATIONS) {
                //System.out.println("Going to send new session key");
                streams = server.sendNewKey(streams, clientSocket);
                if (streams == null)
                    return null;
                currentNumberCommunications = 0;
            }
        }
        return message;
    }

    private void disconnect(){
        server.disconnect(streams);
        sendMessage(username + " just logged out. We will surely miss him/her! :(", null);
        this.interrupt();
    }


}
