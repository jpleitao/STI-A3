import java.io.*;
import java.net.Socket;

public class ChatServerThread extends Thread
{
    private ChatServer       server    = null;
    private Socket socket    = null;
    private int              ID        = -1;
    private DataInputStream streamIn  =  null;
    private DataOutputStream streamOut = null;


    public ChatServerThread(ChatServer _server, Socket _socket)
    {
        super();
        server = _server;
        socket = _socket;
        ID     = socket.getPort();
    }

    // Sends message to client
    public void send(String msg)
    {
        try
        {
            streamOut.writeUTF(msg);
            streamOut.flush();
        }

        catch(IOException ioexception)
        {
            System.out.println(ID + " ERROR sending message: " + ioexception.getMessage());
            server.remove(ID);
            this.interrupt();
            //stop();
        }
    }

    // Gets id for client
    public int getID()
    {
        return ID;
    }

    // Runs thread
    public void run()
    {
        System.out.println("Server Thread " + ID + " running.");

        while (!this.isInterrupted())
        {
            try
            {
                server.handle(ID, streamIn.readUTF());
            }

            catch(IOException ioe)
            {
                System.out.println(ID + " ERROR reading: " + ioe.getMessage());
                server.remove(ID);
                this.interrupt();
                //stop();
            }
        }
    }

    // Opens thread
    public void open() throws IOException
    {
        streamIn = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        streamOut = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
    }

    // Closes thread
    public void close() throws IOException
    {
        if (socket != null)
            socket.close();
        if (streamIn != null)
            streamIn.close();
        if (streamOut != null)
            streamOut.close();
    }

}