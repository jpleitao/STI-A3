package server;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.net.Socket;

public class ServerThread extends Thread{

    private Server server;
    private Socket clientSocket;
    private Server.ObjectStreamBundle streams;

    public ServerThread(Server server, Socket clientSocket) {
        this.server = server;
        this.clientSocket = clientSocket;
    }

    public void run() {
        //FIXME: Meter isto num ciclo infinito ou assim a fazer os passos todos

        System.out.println("Going to wait for the client's session key");
        streams = server.receiveSessionKey(clientSocket);

        //Try sending a string to the client with the received sessionKey
        String message = "Hello from Server";
        boolean result = server.sendMessage(message, streams.outputStream);
        System.out.println("Sent message and the result was " + result);
    }

}
