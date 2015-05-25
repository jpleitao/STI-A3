package client;

public class ClientThread extends Thread{

    private Client client;

    public ClientThread(Client client) {
        this.client = client;
    }

    public void run() {
        while (!this.isInterrupted()) {
            System.out.println("Connected!!!");
            String message = client.readMessage();
            System.out.println("Received " + message);
        }
    }
}
