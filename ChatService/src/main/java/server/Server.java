package server;

import ca.CAThread;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.lang.reflect.ParameterizedType;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class Server {

    private final int portNumber;
    private final String publicKeyFilePath;
    private final String privateKeyFilePath;
    private final String caCertificateFilePath;

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private ServerSocket serverSocket;
    private Cipher cipher;
    private CertificateFactory certificateFactory;
    private X509Certificate caCertificate;

    private static final int KEYSIZE = 512;

    public Server() {
        portNumber = 9996;
        publicKeyFilePath = "Server-PublicKey.ser";
        privateKeyFilePath = "Server-PrivateKey.ser";
        caCertificateFilePath = "CA-Certificate.ser";
        certificateFactory = null;
        caCertificate = null;
    }

    public Server(int port, String publicKeyFilePath, String caCertificateFilePath) {
        portNumber = port;
        this. publicKeyFilePath = publicKeyFilePath;
        this.caCertificateFilePath = caCertificateFilePath;
        certificateFactory = null;
        caCertificate = null;
        privateKeyFilePath = "Server-PrivateKey.ser";
    }
    private boolean loadCertificateFactory() {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
            return true;
        } catch (CertificateException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private boolean connectServer() {
        try {
            serverSocket = new ServerSocket(portNumber);
            return true;
        } catch (IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private StringBuffer convertKeyToString(Key key) {
        byte[] keyEncode = key.getEncoded();
        StringBuffer retString = new StringBuffer();
        for (byte aKeyEncode : keyEncode) {
            retString.append(Integer.toHexString(0x0100 + (aKeyEncode & 0x00FF)).substring(1));
        }
        return retString;
    }

    private boolean generateServerKeys() {
        KeyPair keyPair = generateKeyPair();
        if (keyPair == null)
            return false;
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        //Export both keys to a file
        return exportPublicKeyToFile(publicKeyFilePath) && exportPrivateKeyToFile(privateKeyFilePath);
    }

    private boolean exportPublicKeyToFile(String filePath) {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath));
            oos.writeObject(publicKey);
            oos.close();
            return true;
        } catch(IOException ioe) {
            ioe.getMessage();
            ioe.printStackTrace();
            return false;
        }
    }

    private boolean exportPrivateKeyToFile(String filePath) {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath));
            //FIXME FIXME: ENCRYPT THIS!!!!
            oos.writeObject(privateKey);
            oos.close();
            return true;
        } catch(IOException ioe) {
            ioe.getMessage();
            ioe.printStackTrace();
            return false;
        }
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(KEYSIZE);
            return keyGen.genKeyPair();
        } catch(NoSuchAlgorithmException nsae) {
            nsae.getMessage();
            nsae.printStackTrace();
            return null;
        }
    }

    private boolean loadPublicKeyFromFile() {
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(publicKeyFilePath));
            publicKey = (PublicKey) ois.readObject();
            ois.close();
            return true;
        }catch (ClassNotFoundException | IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private boolean loadPrivateKeyFromFile() {
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(privateKeyFilePath));
            //FIXME FIXME FIXME: THIS SHOULD BE ENCRYPTED!!
            privateKey = (PrivateKey) ois.readObject();
            ois.close();
            return true;
        }catch (ClassNotFoundException | IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private boolean loadKeys() {
        return loadPublicKeyFromFile() && loadPrivateKeyFromFile();
    }

    private boolean loadCACertificate() {
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(caCertificateFilePath));
            caCertificate = (X509Certificate) ois.readObject();
            return true;
        } catch (IOException | ClassNotFoundException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    public void initCipher(int mode, Key key) throws InvalidKeyException, NoSuchPaddingException,
                                                     NoSuchAlgorithmException {
        cipher = Cipher.getInstance("RSA");
        cipher.init(mode, key);
    }

    private String readMessage(Socket socket) {
        try {
            initCipher(Cipher.DECRYPT_MODE, privateKey);

            CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), cipher);
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(cipherInputStream));

            return bufferedReader.readLine();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException e) {
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    private void sendMessage(String message, Socket socket) {
        try {
            initCipher(Cipher.ENCRYPT_MODE, publicKey);//FIXME: Replace this key with the session key to the given client!

            CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), cipher);
            DataOutputStream dataOutputStream = new DataOutputStream(cipherOutputStream);

            System.out.println("Vou enviar " + message);
            dataOutputStream.writeUTF(message);
            //dataOutputStream.close();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException e) {
            e.getMessage();
            e.printStackTrace();
        }
    }

    public boolean authenticateClient(Socket clientSocket) {
        //Reads a client's certificate from the socket and validates it!
        X509Certificate clientCertificate = getClientCertificateFromSocket(clientSocket);
        if (clientCertificate == null)
            return false;
        return validateClientCertificate(clientCertificate);
    }

    private X509Certificate getClientCertificateFromSocket(Socket socket) {

        try {
            initCipher(Cipher.DECRYPT_MODE, privateKey);
            CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), cipher);
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(cipherInputStream));

            System.out.println(bufferedReader.readLine());

            //FIXME: CANNOT READ THE CERTIFICATE SENT FROM THE CLIENT
            //O gajo esta a passar-se a ler so garbage

            return null;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | InvalidKeyException e) {
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    private boolean validateClientCertificate(X509Certificate clientCertificate) {
        try {
            //Check the chain
            List<X509Certificate> mylist = new ArrayList<>();
            mylist.add(clientCertificate);
            CertPath cp = certificateFactory.generateCertPath(mylist);

            TrustAnchor anchor = new TrustAnchor(caCertificate, null);
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            params.setRevocationEnabled(false);

            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            PKIXCertPathValidatorResult pkixCertPathValidatorResult = (PKIXCertPathValidatorResult) cpv.validate(cp, params);

            //FIXME: Ver ao certo o que e que isto retorna
            System.out.println("\n\n\n\n\n\n\n\n\n\n\n" + pkixCertPathValidatorResult);
            return true;
        } catch (NoSuchAlgorithmException | CertificateException | InvalidAlgorithmParameterException | CertPathValidatorException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private void run() {
        while (true) {
            System.out.println("Listening on socket on port " + portNumber +  "...");
            try {
                //Get new connection
                Socket socket = serverSocket.accept();

                //Create thread to deal with the client and start it

                ServerThread clientThread = new ServerThread(this, socket);
                clientThread.start();
            } catch (IOException e) {
                e.getMessage();
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        Server server = new Server();

        /*Load Server's Public and Private Keys from disk*/
        if (!server.loadKeys()) {
            if (!server.generateServerKeys()) {
                System.out.println("Could not generate the server's private and public keys!");
                System.exit(-1);
            }
        }

        if (!server.loadCACertificate()) {
            System.out.println("Could not load the CA's certificate!");
            System.exit(-1);
        }

        if (server.connectServer() && server.loadCertificateFactory()) {
            server.run();
        }
        else{
            System.out.println("Could not connect to server or load certificate factory!");
            System.exit(-1);
        }

    }
}
