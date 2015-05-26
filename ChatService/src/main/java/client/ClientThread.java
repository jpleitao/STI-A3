package client;

public class ClientThread extends Thread{

    private Client client;

    public ClientThread(Client client) {
        this.client = client;
    }

    public void run() {
        //FIXME THIS PART IS BUGGY
        while (!this.isInterrupted()) {

            String message = client.readMessage();
            //System.out.println(message);
            if(message != null && !message.equals(""))//REMEMBER WHEN READ MESSAGE RETURNS "" IT MEANS NEW SESSION KEY!!!!!
                client.sendMessage(message);
        }
    }
}
