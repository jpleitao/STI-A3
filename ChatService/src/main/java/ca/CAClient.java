package ca;

import java.io.*;
import java.net.Socket;
import java.security.cert.X509Certificate;

public abstract class CAClient {

    private final String cAHost;
    private final int cAPort;
    private Socket cAsocket;

    public CAClient() {
        cAHost = "localhost";
        cAPort = 6000;
        cAsocket = null;
    }

    protected boolean requestCertificate(String clientName) {
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
            return true;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return  false;
        }
    }

    private void saveCertificateToFile(X509Certificate certificate, String clientName) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(clientName));
        oos.writeObject(certificate);
        oos.close();
    }

    /*

    public static void main(String[] args) {
        CAClient client = new CAClient();

        if (args.length != 1)
            client.connectToCA("Client");
        else
            client.connectToCA(args[0]);
    }*/
}
