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
            System.out.println("[1]Received " + message);
            if (message == null)
                this.interrupt();

            boolean result = client.sendMessage("OLA");
            System.out.println("[1]Sent message to the server and got result " + result);
            if (!result)
                this.interrupt();

            //Here the key exchange should occur
            System.out.println("Going to receive second message");
            message = client.readMessage();
            System.out.println("[2]Received " + message);
            if (message == null)
                this.interrupt();
            System.out.println("AJAAJJA");
        }
    }
}
