package profStuff;

import java.net.*;
import java.io.*;


public class ChatServer implements Runnable
{  
    private ChatServerThread clients[];
    private ServerSocket server_socket;
    private Thread thread;
    private int clientCount;

    public ChatServer(int port)
    {
        clients = new ChatServerThread[20];
        server_socket = null;
        thread = null;
        clientCount = 0;

        try {
            // Binds to port and starts server
            System.out.println("Binding to port " + port);
            server_socket = new ServerSocket(port);
            System.out.println("Server started: " + server_socket);
        } catch(IOException ioexception) {
            // Error binding to port
            System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
            server_socket = null;
        }
    }

    public Boolean getStatus() {
        return server_socket != null;
    }
    
    public void run()
    {
        while (thread != null)
        {
            try {
                // Adds new thread for new client
                System.out.println("Waiting for a client ...");
                addThread(server_socket.accept());
            } catch(IOException ioexception) {
                System.out.println("Accept error: " + ioexception); stop();
            }
        }
    }

    public void start()
    {
        if (thread == null)
        {
            // Starts new thread for client
            thread = new Thread(this);
            thread.start();
        }
    }
    
    public void stop()
    {
        if (thread != null)
        {
            // Stops running thread for client
            // thread.stop();
            thread.interrupt();
            thread = null;
        }
    }
   
    private int findClient(int ID)
    {
        // Returns client from id
        for (int i = 0; i < clientCount; i++)
        {
            if (clients[i].getID() == ID)
                return i;
        }
        return -1;
    }
    
    public synchronized void handle(int ID, String input)
    {
        if (input.equals(".quit"))
        {
            int leaving_id = findClient(ID);
            // Client exits
            clients[leaving_id].send(".quit");
            // Notify remaing users
            for (int i = 0; i < clientCount; i++)
                    if (i!=leaving_id)
                        clients[i].send("Client " +ID + " exits..");
            remove(ID);
        }
        else
        {
            // Brodcast message for every other client online
            for (int i = 0; i < clientCount; i++)
                clients[i].send(ID + ": " + input);
        }
    }
    
    public synchronized void remove(int ID)
    {
        int pos = findClient(ID);

        if (pos >= 0)
        {
            // Removes thread for exiting client
            ChatServerThread toTerminate = clients[pos];
            System.out.println("Removing client thread " + ID + " at " + pos);
            if (pos < clientCount-1)
            {
                for (int i = pos + 1; i < clientCount; i++)
                    clients[i - 1] = clients[i];
            }
            clientCount--;

            try {
                toTerminate.close();
            } catch(IOException ioe) {
                System.out.println("Error closing thread: " + ioe);
            }

            //toTerminate.stop();
            toTerminate.interrupt();
        }
    }
    
    private void addThread(Socket socket)
    {
        if (clientCount < clients.length)
        {
            // Adds thread for new accepted client
            System.out.println("Client accepted: " + socket);
            clients[clientCount] = new ChatServerThread(this, socket);

            try {
                clients[clientCount].open();
                clients[clientCount].start();
                clientCount++;
            } catch (IOException ioe) {
                System.out.println("Error opening thread: " + ioe);
            }
        } else
            System.out.println("Client refused: maximum " + clients.length + " reached.");
    }

    public static void main(String args[])
    {
        int portNumber;
        ChatServer server;

        if (args.length == 0)
            portNumber = 9000;
        else
            portNumber = Integer.parseInt(args[0]);

        // Calls new server
        server = new ChatServer(portNumber);
        if (server.getStatus())
            server.start();
    }
}
