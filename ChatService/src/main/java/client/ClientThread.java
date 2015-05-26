package client;

public class ClientThread extends Thread{

    private Client client;

    public ClientThread(Client client) {
        this.client = client;
    }

    public void run() {
        //FIXME THIS PART IS BUGGY
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

            System.out.println("AJAAJJA");
        }
    }
}
