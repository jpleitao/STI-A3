package server;

import ca.CAClient;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class Server extends CAClient{

    private final int portNumber;
    private final String publicKeyFilePath;
    private final String privateKeyFilePath;
    private final String caCertificateFilePath;
    private final String sessionKeyAlgorithm;
    private final String serverKeyAlgorithm;
    private final String certificateType;
    private final String certificateFilePath;
    private final String fileEncryptionKey;

    private SecureRandom secureRandom;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private ServerSocket serverSocket;
    private CertificateFactory certificateFactory;
    private X509Certificate caCertificate;
    private X509Certificate certificate;

    private static final int KEYSIZE = 512;
    private static final int SESSIONKEYSIZE = 128;

    public Server() {
        portNumber = 9996;
        publicKeyFilePath = "Server-PublicKey.ser";
        privateKeyFilePath = "Server-PrivateKey.ser";
        caCertificateFilePath = "CA-Certificate.ser";
        certificateFilePath = "Server-Certificate.cer";
        sessionKeyAlgorithm = "AES/CFB8/NoPadding"; //CFB8 sends data in blocks of 8 bits = 1 byte
        serverKeyAlgorithm = "RSA/None/PKCS1Padding";
        fileEncryptionKey = "STI-ChatServer";
        certificateType = "X.509";
        certificateFactory = null;
        caCertificate = null;
        certificate = null;
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
            //Get encryption key based on text
            byte[] input = privateKey.getEncoded();
            System.out.println("Key len=" + input.length);
            byte[] fileEncryptionKeyBytes = fileEncryptionKey.getBytes("UTF-8");

            //Get 128 bit private encryption key from the given string
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            fileEncryptionKeyBytes = sha.digest(fileEncryptionKeyBytes);
            fileEncryptionKeyBytes = Arrays.copyOf(fileEncryptionKeyBytes, 16); // use only first 128 bit

            SecretKeySpec key = new SecretKeySpec(fileEncryptionKeyBytes, "AES");
            Cipher cipherPrivate = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
            cipherPrivate.init(Cipher.ENCRYPT_MODE, key);

            //Actually encrypt the content in the file
            CipherOutputStream cipherOutputStream = new CipherOutputStream(new FileOutputStream(filePath), cipherPrivate);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(cipherOutputStream);
            objectOutputStream.writeObject(privateKey);
            objectOutputStream.close();
            return true;
        } catch(IOException | NoSuchPaddingException| NoSuchAlgorithmException | InvalidKeyException |
                NoSuchProviderException e) {
            e.getMessage();
            e.printStackTrace();
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
            return false;
        }
    }

    private boolean loadPrivateKeyFromFile() {
        try {
            //Get decryption key based on text
            byte[] fileEncryptionKeyBytes = fileEncryptionKey.getBytes("UTF-8");

            //Get 128 bit private encryption key from the given string
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            fileEncryptionKeyBytes = sha.digest(fileEncryptionKeyBytes);
            fileEncryptionKeyBytes = Arrays.copyOf(fileEncryptionKeyBytes, 16); // use only first 128 bits

            SecretKeySpec key = new SecretKeySpec(fileEncryptionKeyBytes, "AES");
            Cipher cipherPrivate = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
            cipherPrivate.init(Cipher.DECRYPT_MODE, key);

            //Actually decrypt the content in the file
            CipherInputStream cipherInputStream = new CipherInputStream(new FileInputStream(privateKeyFilePath), cipherPrivate);
            ObjectInput objectInputStream = new ObjectInputStream(cipherInputStream);
            privateKey = (PrivateKey) objectInputStream.readObject();
            objectInputStream.close();
            return true;
        }catch (IOException | NoSuchPaddingException| NoSuchAlgorithmException | InvalidKeyException |
                NoSuchProviderException | ClassNotFoundException e) {
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

    private boolean loadCertificate() {
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(certificateFilePath));
            certificate = (X509Certificate) ois.readObject();
            return true;
        } catch (IOException | ClassNotFoundException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private Cipher initCipher(int mode, Key key, String method, byte[] iv) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        Cipher out;
        if (mode == Cipher.ENCRYPT_MODE) {
            out = Cipher.getInstance(method, "BC");
            out.init(mode, key, secureRandom);
        }
        else {
            try {
                out = Cipher.getInstance(method, "BC");
                if(iv != null){
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    out.init(mode, key, ivSpec);
                }
                else {
                    out.init(mode, key);
                }

            } catch (InvalidAlgorithmParameterException e){
                e.getMessage();
                e.printStackTrace();
                return null;
            }
        }

        return  out;
    }

    private String readMessage(ObjectInputStream stream) {
        try {
            return (String) stream.readObject();
        } catch (IOException|ClassNotFoundException e){
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    public boolean sendMessage(String message, ObjectOutputStream stream) {
        try{
            stream.writeObject(message);
            stream.flush();
            return true;
        } catch (IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    public boolean sendPublicKeyToClient(Socket socket) {
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());

            //Receive boolean value
            boolean request = objectInputStream.readBoolean();

            if (request) {
                //Send public key to client
                objectOutputStream.writeObject(publicKey);
                objectOutputStream.flush();
            }
            return true;
        } catch(IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }

    }

    public ObjectStreamBundle receiveSessionKey(Socket socket) {
        try{
            //Use private key to decrypt session key
            Cipher rsaCipher = initCipher(Cipher.DECRYPT_MODE, privateKey, serverKeyAlgorithm, null);
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            byte [] encryptedSessionKey = (byte[])objectInputStream.readObject();

            byte[] sessionKeyEncoded = rsaCipher.doFinal(encryptedSessionKey);
            SecretKey sessionKey =  new SecretKeySpec(sessionKeyEncoded, 0, sessionKeyEncoded.length, "AES") ;

            //Receiving the initial IV for the input cypher
            byte [] inputIV = (byte[])objectInputStream.readObject();
            Cipher inputCipher = initCipher(Cipher.DECRYPT_MODE, sessionKey, sessionKeyAlgorithm, inputIV);

            //Sending the initial IV of the output cipher
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            Cipher outputCipher = initCipher(Cipher.ENCRYPT_MODE, sessionKey, sessionKeyAlgorithm, null);
            objectOutputStream.writeObject(outputCipher.getIV());
            objectOutputStream.flush();

            //Creating the real communications stream
            CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), outputCipher);
            ObjectOutputStream outputStream = new ObjectOutputStream(cipherOutputStream);
            outputStream.flush();
            CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), inputCipher);
            ObjectInputStream inputStream = new ObjectInputStream(cipherInputStream);

            return  new ObjectStreamBundle(inputStream, outputStream);
        } catch(IOException | ClassNotFoundException | NoSuchPaddingException | NoSuchAlgorithmException |
                IllegalBlockSizeException| BadPaddingException | NoSuchProviderException | InvalidKeyException e){
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    public boolean sendCertificateToClient(ObjectOutputStream outputStream) {
        try {
            System.out.println("Going to send the certificate to the client");
            outputStream.writeObject(certificate);
            outputStream.flush();
            return true;
        } catch (IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    public boolean receiveAndValidateServerCertificate(ObjectInputStream inputStream) {
        try {
            X509Certificate clientCertificate = (X509Certificate) inputStream.readObject();
            return validateClientCertificate(clientCertificate);
        } catch(IOException | ClassNotFoundException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
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

            return pkixCertPathValidatorResult != null;
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
            if(!server.requestCertificate(server.caCertificateFilePath)) {
                System.out.println("Could not connect with CA!");
                System.exit(-1);
            }
        }

        if (!server.loadCertificate()) {
            if (!server.requestCertificate("certificateFilePath")) {
                System.out.println("Could not connect with CA!");
                System.exit(-1);
            }
        }

        if (server.connectServer() && server.loadCertificateFactory()) {
            server.run();
        }
        else{
            System.out.println("Could not connect to server or load certificate factory!");
            System.exit(-1);
        }

    }

    public class ObjectStreamBundle{
        public ObjectOutputStream outputStream;
        public ObjectInputStream inputStream;

        public ObjectStreamBundle(ObjectInputStream in, ObjectOutputStream out) {
            inputStream = in;
            outputStream = out;
        }
    }
}
