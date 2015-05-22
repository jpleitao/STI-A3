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
        System.out.println("Going to generate a session key to the client");
        //Generate session key
        sessionKey = server.generateSessionKey();
        boolean result = server.sendKeyToClient(clientSocket, sessionKey.getEncoded(), null);
        if (!result)
            System.out.println("Error sending key to client!");
    }

}
