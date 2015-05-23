package server;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
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
    private final String sessionKeyAlgorithm;
    private final String serverKeyAlgorithm;
    private final String certificateType;

    private SecureRandom secureRandom;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private ServerSocket serverSocket;
    private Cipher cipher;
    private CertificateFactory certificateFactory;
    private X509Certificate caCertificate;

    private static final int KEYSIZE = 512;
    private static final int SESSIONKEYSIZE = 128;

    public Server() {
        portNumber = 9996;
        publicKeyFilePath = "Server-PublicKey.ser";
        privateKeyFilePath = "Server-PrivateKey.ser";
        caCertificateFilePath = "CA-Certificate.ser";
        sessionKeyAlgorithm = "AES/CBC/PKCS5Padding";
        serverKeyAlgorithm = "RSA/None/PKCS1Padding";
        certificateType = "X.509";
        certificateFactory = null;
        caCertificate = null;
        secureRandom = new SecureRandom();
    }

    private boolean loadCertificateFactory() {
        try {
            certificateFactory = CertificateFactory.getInstance(certificateType);
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

    private boolean generateServerKeys() {
        System.out.println("Going to generate new keys");
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
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            keyGen.initialize(KEYSIZE);
            return keyGen.genKeyPair();
        } catch(NoSuchAlgorithmException| NoSuchProviderException e) {
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    public SecretKey generateSessionKey(){
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(sessionKeyAlgorithm);
            keyGen.init(SESSIONKEYSIZE);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.getMessage();
            e.printStackTrace();
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

    public void initCipher(int mode, Key key, String method) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        cipher = Cipher.getInstance(method, "BC");
        if (mode == Cipher.ENCRYPT_MODE)
            cipher.init(mode, key, secureRandom);
        else
            cipher.init(mode, key);
    }

    private byte[] readMessage(Socket socket, Key key) {

        return null;
    }

    public boolean sendMessage(byte[] message, Socket socket, Key key) {
        try{
            initCipher(Cipher.ENCRYPT_MODE, key, sessionKeyAlgorithm);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), cipher);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(cipherOutputStream);
            objectOutputStream.writeObject(message);
            objectOutputStream.close();
            return true;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    public SecretKey receiveSessionKey(Socket socket) {
        try{
            //Initialize cipher
            initCipher(Cipher.DECRYPT_MODE, privateKey, serverKeyAlgorithm);
            //Get InputStream
            CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), cipher);
            ObjectInputStream objectOutputStream = new ObjectInputStream(cipherInputStream);
            //Read object and create a new key from the object read
            byte[] object = (byte[]) objectOutputStream.readObject();
            return new SecretKeySpec(object, 0, object.length, sessionKeyAlgorithm);
        } catch(IOException | ClassNotFoundException | NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e){
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    public boolean sendKeyToClient(Socket clientSocket, byte[] keyEncoded, Key previousKey) {

        //New Session Key -- Message to send first

        return false;
    }

    public boolean authenticateClient(Socket clientSocket) {
        //Reads a client's certificate from the socket and validates it!
        //X509Certificate clientCertificate = getClientCertificateFromSocket(clientSocket);
        //return clientCertificate != null && validateClientCertificate(clientCertificate);

        //FIXME: CHANGE THIS TO READ THE CERTIFICATE
        byte[] message = readMessage(clientSocket, privateKey);
        System.out.println("Read " + message.length + " bytes");

        return false;
    }

    private X509Certificate getClientCertificateFromSocket(Socket socket) {
        //Read the client's certificate from the socket and validate it
        try {
            //Read certificate from socket
            System.out.println("Vou ler o certificado");
            byte[] certificateEncoded = readMessage(socket, privateKey);

            System.out.println("GOT " + Arrays.toString(certificateEncoded));

            //Convert it to a X509Certificate certificate
            return certificateEncoded==null ? null:(X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateEncoded));
        } catch (CertificateException e) {
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
        //Add Bouncy Castle as Provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        Server server = new Server();

        /*Load Server's Public and Private Keys from disk*/
        if (!server.loadKeys()) {
            System.out.println("No Key, going to generate");
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
