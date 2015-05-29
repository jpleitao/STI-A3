package client;

public class ClientThread extends Thread{

    private Client client;

    public ClientThread(Client client) {
        this.client = client;
    }

    public void run() {
        while (!this.isInterrupted()) {

            String message = client.readMessage();
            if(message == null && !client.isShutdown()) {
                if (!this.isInterrupted())
                    client.stop(Client.GoodbyeMessage.CONNECTION_ERROR);
            }
            else if(message != null && !message.equals(""))
                System.out.println(message);
        }
    }
}
