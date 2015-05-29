package profStuff;

import java.net.*;
import java.io.*;


public class ChatClient implements Runnable
{  
    private Socket socket              = null;
    private Thread thread              = null;
    private BufferedReader  console   = null;
    private DataOutputStream streamOut = null;
    private ChatClientThread client    = null;

    public ChatClient(String serverName, int serverPort)
    {
        System.out.println("Establishing connection to server...");

        try {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);
        } catch(UnknownHostException uhe) {
            // Host unkwnown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage());
        } catch(IOException ioexception) {
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage());
        }
    }

    public void run()
    {
       while (thread != null)
       {
           try {
               // Sends message from console to server
               streamOut.writeUTF(console.readLine());
               streamOut.flush();
           } catch(IOException ioexception) {
               System.out.println("Error sending string to server: " + ioexception.getMessage());
               stop();
           }
       }
    }


    public void handle(String msg)
    {
        // Receives message from server
        if (msg.equals(".quit"))
        {
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        }
        else
        {
            // else, writes message received from server to console
            System.out.println(msg);
        }
    }

    // Inits new client thread
    public void start() throws IOException
    {
        console = new BufferedReader(new InputStreamReader(System.in));
        streamOut = new DataOutputStream(socket.getOutputStream());

        if (thread == null)
        {
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);
            thread.start();
        }
    }

    // Stops client thread
    public void stop()
    {
        if (thread != null)
        {
            //thread.stop();
            thread.interrupt();
            thread = null;
        }
        try {
            if (console   != null)
                console.close();
            if (streamOut != null)
                streamOut.close();
            if (socket    != null)
                socket.close();
        } catch(IOException ioe) {
            System.out.println("Error closing thread...");
        }

        client.close();
        //client.stop();
        client.interrupt();
    }


    public static void main(String args[])
    {
        ChatClient client = null;
        String host;
        int portNumber;

        if (args.length < 2)
        {
            host = "localhost";
            portNumber = 9000;
        }
        else
        {
            host = args[0];
            portNumber = Integer.parseInt(args[1]);
        }

        try
        {
            // Calls new client
            client = new ChatClient(host, portNumber);
            client.start();
        } catch(IOException ioexception) {
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage());
        }
    }
}