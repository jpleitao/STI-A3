package server;

import javax.crypto.SecretKey;
import java.net.Socket;

public class ServerThread extends Thread{

    private Server server;
    private Socket clientSocket;
    private SecretKey sessionKey;

    public ServerThread(Server server, Socket clientSocket) {
        this.server = server;
        this.clientSocket = clientSocket;
    }

    public void run() {
        //FIXME: Meter isto num ciclo infinito ou assim a fazer os passos todos

        System.out.println("Going to wait for the client's session key");
        sessionKey = server.receiveSessionKey(clientSocket);
        System.out.println("Received sessionKey " + sessionKey);

        //Try sending a string to the client with the received sessionKey
        String message = "Hello from Server";
        boolean result = server.sendMessage(message.getBytes(), clientSocket, sessionKey);
        System.out.println("Sent message and the result was " + result);
    }

}
