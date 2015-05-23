package client;

import ca.CAClient;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Client extends CAClient{

    private final int portNumber;
    private final String serverPublicKeyFilePath;
    private final String serverHost;
    private final String sessionKeyAlgorithm;
    private final String serverEncryptionAlgorithm;
    private final int SESSIONKEYSIZE;
    private final String certificateType;
    private final String caCertificateFilePath;

    private SecureRandom secureRandom;
    private Key serverPublicKey;
    private SecretKey communicationKey; //The session key
    private Socket socket;
    private ObjectInputStream inputStream;
    private ObjectOutputStream outputStream;
    private X509Certificate certificate;
    private X509Certificate caCertificate;
    private String name;
    private CertificateFactory certificateFactory;

    public Client(String name) {
        portNumber = 9996;
        SESSIONKEYSIZE = 128;
        serverPublicKeyFilePath = "Server-PublicKey.ser";
        serverHost = "localhost";
        sessionKeyAlgorithm = "AES/CFB8/NoPadding";
        serverEncryptionAlgorithm = "RSA/None/PKCS1Padding";
        serverPublicKey = null;
        communicationKey = null;
        socket = null;
        certificate = null;
        this.name = name;
        secureRandom = new SecureRandom();
        certificateFactory = null;
        certificateType = "X.509";
        caCertificate = null;
        caCertificateFilePath = "CA-Certificate.ser";
    }

    private boolean connectToServer(boolean requestServerPublicKey) {
        try {
            socket = new Socket(serverHost, portNumber);

            if (!getServerPublicKey(socket, requestServerPublicKey)) {
                System.out.println("Could not request server public key");
                return false;
            }

            //Generate a session key and send it to the server
            communicationKey = generateSessionKey();
            if(!sendSessionKey(communicationKey)) {
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

    private boolean getServerPublicKey(Socket socket, boolean sendRequest) {

        try {
            //Send the server a boolean value to inform of the client's need to get its public key
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());

            objectOutputStream.writeBoolean(sendRequest);
            objectOutputStream.flush();

            if (sendRequest)
                serverPublicKey = (Key) objectInputStream.readObject();
            return true;
        } catch (IOException | ClassNotFoundException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private SecretKey generateSessionKey(){
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(SESSIONKEYSIZE);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.getMessage();
            e.printStackTrace();
            return null;
        }
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
            return false;
        }
    }

    private boolean sendCertificateToServer() {
        try {
            outputStream.writeObject(certificate);
            outputStream.flush();
            return true;
        } catch (IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private boolean receiveAndValidateServerCertificate() {

        try {
            X509Certificate serverCertificate = (X509Certificate) inputStream.readObject();
            return validateServerCertificate(serverCertificate);
        } catch (ClassNotFoundException | IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private boolean validateServerCertificate(X509Certificate certificate) {
        try {
            //Check the chain
            List<X509Certificate> mylist = new ArrayList<>();
            mylist.add(certificate);
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
    private Cipher initCipher(int mode, Key key, String method, byte[] iv) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        Cipher out;
        if (mode == Cipher.ENCRYPT_MODE) {
             out = Cipher.getInstance(method, "BC");
            out.init(mode, key, secureRandom);
        }
        else {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            try {
                out = Cipher.getInstance(method, "BC");
                out.init(mode, key, ivSpec);
            } catch (InvalidAlgorithmParameterException e){
                e.getMessage();
                e.printStackTrace();
                return null;
            }
        }
        return out;
    }

    public boolean sendMessage(String message) {
        try{
            outputStream.writeObject(message);
            outputStream.flush();
            return true;
        } catch (IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private String readMessage() {
        try {
            return (String) inputStream.readObject();
        } catch (IOException|ClassNotFoundException e){
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    private boolean sendSessionKey(SecretKey sessionKey) {

        if (sessionKey == null)
            return false;

        try{
            //Encrypt with the server's public key
            Cipher rsaCipher = initCipher(Cipher.ENCRYPT_MODE, serverPublicKey, serverEncryptionAlgorithm, null);
            byte [] sessionKeyEncripted = rsaCipher.doFinal(sessionKey.getEncoded());

            //Sending the session key encrypted
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(sessionKeyEncripted);
            objectOutputStream.flush();

            //Sending the initial IV of the output cipher
            Cipher outputCipher = initCipher(Cipher.ENCRYPT_MODE, sessionKey, sessionKeyAlgorithm, null);
            objectOutputStream.writeObject(outputCipher.getIV());
            objectOutputStream.flush();

            //Receiving the initial IV for the input cypher
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            byte [] inputIV = (byte[])objectInputStream.readObject();
            Cipher inputCipher = initCipher(Cipher.DECRYPT_MODE, sessionKey, sessionKeyAlgorithm, inputIV);

            //Creating the real communications stream
            CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), inputCipher);
            inputStream = new ObjectInputStream(cipherInputStream);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), outputCipher);
            outputStream = new ObjectOutputStream(cipherOutputStream);
            outputStream.flush();

            return true;
        } catch (IllegalBlockSizeException | BadPaddingException | IOException | InvalidKeyException | NoSuchPaddingException
                | NoSuchProviderException |NoSuchAlgorithmException | ClassNotFoundException e){
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        //Call it Magic: Add Bouncy Castle as Provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        boolean requestServerPublicKey = false;

        Client client;
        if (args.length != 1)
            client = new Client("Client");
        else
        //Create the client and connect it to the Chat Server
            client = new Client(args[0]);

        if (!client.loadCertificateFactory()) {
            System.out.println("Could not load certificate factory");
            System.exit(-1);
        }

        if (!client.loadCACertificate()) {
            if(!client.requestCertificate(client.caCertificateFilePath)) {
                System.out.println("Could not connect with CA!");
                System.exit(-1);
            }
        }

        if (!client.loadClientCertificate()) {
            if(!client.requestCertificate(client.name)) {
                System.out.println("Could not connect with CA!");
                System.exit(1);
            }
        }

        if(!client.loadServerPublicKey()){
            //Request the server's public key after establishing the connection
            requestServerPublicKey = true;
            System.out.println("Could not load server key. Will request it upon connection");
        }

        if (client.connectToServer(requestServerPublicKey)) {
            //Receive certificate from Server and validate it
            if (!client.receiveAndValidateServerCertificate()) {
                System.out.println("Could not receive Server's Certificate or invalid Server's Certificate");
                System.exit(-1);
            }

            //Send Certificate to Server
            if (!client.sendCertificateToServer()) {
                System.out.println("Could not send certificate to server");
                System.exit(-1);
            }

            System.out.println("Estou ligado!!!");
            String message = client.readMessage();
            System.out.println("Recebi " + message);


            // FIXME: GENERATE A PAIR PUBLIC KEY - PRIVATE KEY FOR THE CLIENT, SINCE WE ARE GOING TO NEED IT FOR
            // ASSURING THE AUTENTICITY, INTEGRITY AND NON-REPUDIATION OF THE MESSAGES

            // FIXME: DO NOT FORGET TO SIGN ALL THE MESSAGES SENT TO THE SERVER AND CHECK THE INTEGRITY OF THE MESSAGES
            // RECEIVED FROM THE SERVER
        }
    }
}
