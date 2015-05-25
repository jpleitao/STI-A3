package client;


import java.net.Socket;

public class ClientThread extends Thread{

    private Socket socket;
    private Client client;

    public ClientThread(Socket socket, Client client) {
        this.socket = socket;
        this.client = client;
    }

    public void run() {
        while (!this.isInterrupted()) {
            System.out.println("Estou ligado!!!");
            String message = client.readMessage();
            System.out.println("Recebi " + message);
        }
    }
}
