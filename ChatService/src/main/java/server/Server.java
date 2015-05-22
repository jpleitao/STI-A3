package server;

import javax.crypto.*;
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
        sessionKeyAlgorithm = "AES";
        certificateFactory = null;
        caCertificate = null;
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
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(KEYSIZE);
            return keyGen.genKeyPair();
        } catch(NoSuchAlgorithmException nsae) {
            nsae.getMessage();
            nsae.printStackTrace();
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

    public void initCipher(int mode, Key key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        cipher = Cipher.getInstance("RSA");
        cipher.init(mode, key);
    }

    private byte[] decryptMessage(byte[] messageEncrypted, Key key) {
        try{
            initCipher(Cipher.DECRYPT_MODE, key);

            byte[] decrypted = new byte[cipher.getOutputSize(messageEncrypted.length)];
            int dec_len = cipher.update(messageEncrypted, 0, messageEncrypted.length, decrypted, 0);
            cipher.doFinal(decrypted, dec_len);
            decrypted = filterMessage(decrypted);
            return decrypted;
        } catch(BadPaddingException | IllegalBlockSizeException | ShortBufferException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e){
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    private byte[] encryptMessage(byte[] messageToEncrypt, Key key) {
        try{
            initCipher(Cipher.ENCRYPT_MODE, key);

            byte[] encrypted = new byte[cipher.getOutputSize(messageToEncrypt.length)];
            int enc_len = cipher.update(messageToEncrypt, 0, messageToEncrypt.length, encrypted, 0);
            cipher.doFinal(encrypted, enc_len);
            return encrypted;
        } catch(BadPaddingException | IllegalBlockSizeException | ShortBufferException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e){
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    private byte[] readMessage(Socket socket, Key key) {
        try {
            byte[] data = new byte[64];
            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            int received = dataInputStream.read(data);
            System.out.println("Before Decryption " + Arrays.toString(data));
            byte[] decryptedData = decryptMessage(data, key);
            System.out.println("After Decryption " + Arrays.toString(decryptedData));

            System.out.println("STRING: " + new String(decryptedData));

            return data;
        } catch (IOException e) {
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    private boolean sendMessage(byte[] message, Socket socket, Key key) {
        try {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            byte[] messageEncrypted = encryptMessage(message, key);
            if (messageEncrypted == null)
                return false;
            System.out.println("Vou enviar " + Arrays.toString(messageEncrypted) + " com len " + messageEncrypted.length);
            dataOutputStream.write(messageEncrypted, 0, messageEncrypted.length);
            return true;
        } catch (IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private byte[] filterMessage(byte[] byteArray) {
        int i;

        for (i=byteArray.length-1; i>= 0; i--) {
            if (byteArray[i] != (byte)0)
                break;
        }

        if (i >= 0){
            byte[] result = new byte[i+1];
            System.arraycopy(byteArray, 0, result, 0, i + 1);
            return result;
        }
        return null;
    }

    public boolean sendKeyToClient(Socket clientSocket, byte[] keyEncoded, Key previousKey) {
        boolean result;
        if (previousKey == null) {
            //First time the client connected, no need to send him the message code to change keys
            result = sendMessage(keyEncoded, clientSocket, privateKey);
        }
        else {
            String message = "New Session Key";
            result = sendMessage(message.getBytes(), clientSocket, previousKey);
            if (!result)
                return false;
            result = sendMessage(keyEncoded, clientSocket, previousKey);
        }
        return result;
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

    private StringBuffer convertKeyToString(Key key) {
        byte[] keyEncode = key.getEncoded();
        StringBuffer retString = new StringBuffer();
        for (byte aKeyEncode : keyEncode) {
            retString.append(Integer.toHexString(0x0100 + (aKeyEncode & 0x00FF)).substring(1));
        }
        return retString;
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
