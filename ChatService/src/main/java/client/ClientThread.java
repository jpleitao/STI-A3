package client;

public class ClientThread extends Thread{

    private Client client;

    public ClientThread(Client client) {
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
