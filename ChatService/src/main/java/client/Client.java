package client;

import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.Data;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Client {

    private final int portNumber;
    private final String serverPublicKeyFilePath;
    private final String serverHost;

    private Key serverPublicKey;
    private Key communicationKey; //The session key
    private Socket socket;
    private Cipher cipher;
    private X509Certificate certificate;
    private String name;

    public Client(String name) {
        portNumber = 9996;
        serverPublicKeyFilePath = "Server-PublicKey.ser";
        serverHost = "localhost";
        serverPublicKey = null;
        communicationKey = null;
        socket = null;
        cipher = null;
        certificate = null;
        this.name = name;
    }

    private boolean connectToServer() {
        try {
            socket = new Socket(serverHost, portNumber);
            boolean result = this.authenticate();
            System.out.println("O authenticate deu " + result);
            return result;
        } catch(IOException ioexception) {
            ioexception.printStackTrace();
            return false;
        }
    }

    private boolean loadStuff() {
        return this.loadServerPublicKey() && this.loadClientCertificate();
    }

    private boolean loadServerPublicKey() {
        try {
            FileInputStream fileInputStream = new FileInputStream(serverPublicKeyFilePath);
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            serverPublicKey = (Key) objectInputStream.readObject();
            return true;
        } catch(IOException | ClassNotFoundException exception) {
            exception.printStackTrace();
            return false;
        }
    }

    private boolean loadClientCertificate() {
        try{
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(name + "-Certificate.cer"));
            certificate = (X509Certificate) ois.readObject();
            return true;
        } catch(IOException | ClassNotFoundException exception) {
            exception.printStackTrace();
            return false;
        }
    }

    private void initCipher(int mode, Key key) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException {
        cipher = Cipher.getInstance("RSA");
        cipher.init(mode, key);
    }

    private String readMessage() throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IOException {
        initCipher(Cipher.DECRYPT_MODE, communicationKey);

        CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), cipher);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(cipherInputStream));

        return bufferedReader.readLine();
    }

    private void sendMessage(String message) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IOException {

        System.out.println("Entrei no sendMessage");
        initCipher(Cipher.ENCRYPT_MODE, serverPublicKey);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), cipher);
        DataOutputStream dataOutputStream = new DataOutputStream(new DataOutputStream(cipherOutputStream));

        System.out.println("Vou enviar " + message);
        dataOutputStream.writeUTF(message);
        dataOutputStream.close();
    }

    private boolean sendCertificate() {
        try {
            initCipher(Cipher.ENCRYPT_MODE, serverPublicKey);
            String certificateString = certToString(certificate);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), cipher);
            DataOutputStream dataOutputStream = new DataOutputStream(cipherOutputStream);

            //FIXME: THIS IS NOT WORKING!!!

            System.out.println("Vou enviar " + certificateString);
            dataOutputStream.writeUTF(certificateString);
            //dataOutputStream.close();
            System.out.println("Enviei");

            return true;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
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

    private boolean authenticate() {
        ////
        // Connect to the server, sending in the first place the client's certificate encrypted with the server's
        // public key
        ////

        //FIXME: This may get changed so that the Server sends its certificate first!!
        return sendCertificate();
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Invalid arguments! Please call: java CAClient <Client-Name>");
            return ;
        }
        boolean result;
        String message = "OLA";

        try {
            //Create the client and connect it to the Chat Server
            Client client = new Client(args[0]);
            result = client.loadStuff();
            if (!result) {
                System.out.println("Could not load the client's certificate or the server's public key. Please try again later...");
                System.exit(1);
            }
            result = client.connectToServer();
            if (result)
                client.sendMessage(message);
        } catch(IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException ioe) {
            ioe.printStackTrace();
        }
    }
}
