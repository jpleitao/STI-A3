package server;

import java.net.Socket;
import java.security.Key;

public class ServerThread extends Thread{

    private Server server;
    private Socket clientSocket;
    private Key sessionKey;

    public ServerThread(Server server, Socket clientSocket) {
        this.server = server;
        this.clientSocket = clientSocket;
    }

    public void run() {
        /*FIXME: Meter isto num ciclo infinito ou assim a fazer os passos todos de autenticaçao e assim (Comecei por
        fazer o cliente mandar o certificado, depois podmeos trocar e o servidor mandar primeiro
         */
        System.out.println("Going to authenticate client");
        boolean result = server.authenticateClient(clientSocket);
        System.out.println("Client authentication result: " + result);
    }

}
