package server;

import java.io.*;
import java.net.Socket;
import java.security.cert.X509Certificate;

public class ServerCAClient {

    private final String cAHost;
    private final int cAPort;
    private Socket cAsocket;

    public ServerCAClient() {
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
        if (args.length != 1) {
            System.out.println("Invalid arguments! Please call: java CAClient <Client-Name>");
            return;
        }

        ServerCAClient client = new ServerCAClient();
        client.connectToCA(args[0]);
    }
}
