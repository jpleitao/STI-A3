package client;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.Socket;
import java.security.cert.CertificateEncodingException;
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
        FileWriter fw = new FileWriter(clientName + "-Certificate.cer");
        fw.write(certToString(certificate));
        fw.close();
    }

    private String certToString(X509Certificate cert) {
        StringWriter sw = new StringWriter();
        try {
            sw.write("-----BEGIN CERTIFICATE-----\n");
            sw.write(DatatypeConverter.printBase64Binary(cert.getEncoded()).replaceAll("(.{64})", "$1\n"));
            sw.write("\n-----END CERTIFICATE-----\n");
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return sw.toString();
    }


    public static void main(String[] args) {

        if (args.length != 1) {
            System.out.println("Invalid arguments! Please call: java CAClient <Client-Name>");
            return ;
        }

        CAClient client = new CAClient();

        client.connectToCA(args[0]);

    }
}
