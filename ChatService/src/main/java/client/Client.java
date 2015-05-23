package client;

import javax.crypto.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;

public class Client {

    private final int portNumber;
    private final String serverPublicKeyFilePath;
    private final String serverHost;
    private final String sessionKeyAlgorithm;
    private final String serverEncryptionAlgorithm;
    private final int SESSIONKEYSIZE;

    private SecureRandom secureRandom;
    private Key serverPublicKey;
    private SecretKey communicationKey; //The session key
    private Socket socket;
    private Cipher cipher;
    private X509Certificate certificate;
    private String name;

    public Client(String name) {
        portNumber = 9996;
        SESSIONKEYSIZE = 128;
        serverPublicKeyFilePath = "Server-PublicKey.ser";
        serverHost = "localhost";
        sessionKeyAlgorithm = "AES/CBC/PKCS5Padding";
        serverEncryptionAlgorithm = "RSA/None/PKCS1Padding";
        serverPublicKey = null;
        communicationKey = null;
        socket = null;
        cipher = null;
        certificate = null;
        this.name = name;
        secureRandom = new SecureRandom();
    }

    private boolean connectToServer() {
        try {
            socket = new Socket(serverHost, portNumber);
            //Generate a session key and send it to the server
            SecretKey newCommunicationKey = generateSessionKey();
            if(!sendSessionKey(newCommunicationKey)) {
                System.out.println("Could not send session key to the server!");
                return false;
            }
            System.out.println("Successfully sent session key to the Server");
            return true;
        } catch(IOException ioexception) {
            ioexception.printStackTrace();
            return false;
        }
    }

    private SecretKey generateSessionKey(){
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

    private boolean loadStuff() {
        return this.loadServerPublicKey() && this.loadClientCertificate();
    }

    private boolean loadServerPublicKey() {
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(serverPublicKeyFilePath));
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

    private void initCipher(int mode, Key key, String method) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        cipher = Cipher.getInstance(method, "BC");
        if (mode == Cipher.ENCRYPT_MODE)
            cipher.init(mode, key, secureRandom);
        else
            cipher.init(mode, key);
    }

    private String readMessage() {
        try{
            //Initialize cipher
            initCipher(Cipher.DECRYPT_MODE, communicationKey, sessionKeyAlgorithm);
            //Get InputStream
            CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), cipher);
            ObjectInputStream objectOutputStream = new ObjectInputStream(cipherInputStream);
            //Read object and create a new key from the object read
            byte[] object = (byte[]) objectOutputStream.readObject();
            return new String(object);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | ClassNotFoundException | NoSuchProviderException | IOException e) {
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    private boolean sendMessage() {
        return true;
    }

    private boolean sendSessionKey(SecretKey sessionKey) {
        try{
            //Encrypt with the server's public key
            initCipher(Cipher.ENCRYPT_MODE, serverPublicKey, serverEncryptionAlgorithm);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), cipher);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(cipherOutputStream);
            objectOutputStream.writeObject(sessionKey.getEncoded());
            objectOutputStream.close();
            return true;
        } catch (IOException | InvalidKeyException | NoSuchPaddingException | NoSuchProviderException |NoSuchAlgorithmException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        //Call it Magic: Add Bouncy Castle as Provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        Client client;
        if (args.length != 1)
            client = new Client("Client");
        else
        //Create the client and connect it to the Chat Server
            client = new Client(args[0]);

        if (!client.loadStuff()) {
            System.out.println("Could not load the client's certificate or the server's public key. Please try again later...");
            System.exit(1);
        }
        if (client.connectToServer()) {
            System.out.println("Estou ligado!!!");
            String message = client.readMessage();
            System.out.println("Recebi " + message);
        }
    }
}
