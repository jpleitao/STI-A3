package server;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
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
    private CertificateFactory certificateFactory;
    private X509Certificate caCertificate;

    private static final int KEYSIZE = 512;
    private static final int SESSIONKEYSIZE = 128;

    public Server() {
        portNumber = 9996;
        publicKeyFilePath = "Server-PublicKey.ser";
        privateKeyFilePath = "Server-PrivateKey.ser";
        caCertificateFilePath = "CA-Certificate.ser";
        sessionKeyAlgorithm = "AES/CFB8/NoPadding"; //CFB8 sends data in blocks of 8 bits = 1 byte
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
            //FIXME: See how to encrypt this!!
            //initCipher(Cipher.ENCRYPT_MODE, publicKey, serverKeyAlgorithm);
            //CipherOutputStream cipherOutputStream = new CipherOutputStream(new FileOutputStream(filePath), cipher);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(filePath));
            objectOutputStream.writeObject(privateKey);
            objectOutputStream.close();
            return true;
        } catch(IOException /*| NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException*/ e) {
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
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private boolean loadPrivateKeyFromFile() {
        try {
            //FIXME: See how to decrypt this!!
            //initCipher(Cipher.DECRYPT_MODE, privateKey, serverKeyAlgorithm);
            //CipherInputStream cipherInputStream = new CipherInputStream(new FileInputStream(privateKeyFilePath), cipher);
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(privateKeyFilePath));
            privateKey = (PrivateKey) ois.readObject();
            ois.close();
            return true;
        }catch (ClassNotFoundException | IOException /*| NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException */ e) {
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

            /*
            //Get InputStream
            CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), outputCipher);
            ObjectInputStream objectInputStream = new ObjectInputStream(cipherInputStream);
            //Read object and create a new key from the object read
            byte[] object = (byte[]) objectInputStream.readObject();
            //objectInputStream.close();
            return new SecretKeySpec(object, 0, object.length, "AES");*/
        } catch(IOException | ClassNotFoundException | NoSuchPaddingException | NoSuchAlgorithmException |
                IllegalBlockSizeException| BadPaddingException | NoSuchProviderException | InvalidKeyException e){
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    public boolean sendKeyToClient(Socket clientSocket, byte[] keyEncoded, Key previousKey) {

        //New Session Key -- Message to send first

        return false;
    }

    /*FIXME I commented these 2 methods because the read message conflicted with the new one
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
    }*/

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

    public class ObjectStreamBundle{
        public ObjectOutputStream outputStream;
        public ObjectInputStream inputStream;

        public ObjectStreamBundle(ObjectInputStream in, ObjectOutputStream out) {
            inputStream = in;
            outputStream = out;
        }
    }
}
