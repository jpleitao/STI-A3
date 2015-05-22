package client;

import java.io.*;
import java.net.Socket;
import java.security.cert.X509Certificate;

public class CAClient {

    private final String cAHost;
    private final int cAPort;
    private Socket cAsocket;

    public CAClient() {
        cAHost = "localhost";
        cAPort = 6000;
        cAsocket = null;
    }

    private void connectToCA(String clientName) {
        try {
            cAsocket = new Socket(cAHost, cAPort);

            ObjectInputStream objectInputStream = new ObjectInputStream(cAsocket.getInputStream());
            DataOutputStream dataOutputStreamCA = new DataOutputStream(cAsocket.getOutputStream());

            //Send client name
            dataOutputStreamCA.writeUTF(clientName);

            //Get certificate
            X509Certificate certificate = (X509Certificate) objectInputStream.readObject();

            //Save it to a file
            saveCertificateToFile(certificate, clientName);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    private void saveCertificateToFile(X509Certificate certificate, String clientName) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(clientName + "-Certificate.cer"));
        oos.writeObject(certificate);
        oos.close();
    }

    public static void main(String[] args) {
        CAClient client = new CAClient();

        if (args.length != 1)
            client.connectToCA("Client");
        else
            client.connectToCA(args[0]);
    }
}
