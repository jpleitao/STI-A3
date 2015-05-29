package server;

import common.ConnectionRequestObject;
import common.PackageBundleObject;
import common.SessionKeyObject;
import org.apache.commons.codec.digest.DigestUtils;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Server {

    private final int portNumber;
    private final int portNumber2;
    private final String publicKeyFilePath;
    private final String privateKeyFilePath;
    private final String sessionKeyAlgorithm;
    private final String serverKeyAlgorithm;
    private final String fileEncryptionKey;
    private final String userDatabaseFilePath;

    private SecureRandom secureRandom;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private ServerSocket serverSocket;
    private Database database;

    private List<ObjectOutputStream> activeClients;

    private static final int KEYSIZE = 512;
    private static final int SESSIONKEYSIZE = 128;

    public Server() {
        portNumber = 9996;
        portNumber2 = 9997;
        publicKeyFilePath = "Server-PublicKey.ser";
        privateKeyFilePath = "Server-PrivateKey.ser";
        sessionKeyAlgorithm = "AES/CFB8/NoPadding"; //CFB8 sends data in blocks of 8 bits = 1 byte
        serverKeyAlgorithm = "RSA/None/PKCS1Padding";
        fileEncryptionKey = "STI-ChatServer";
        secureRandom = new SecureRandom();
        userDatabaseFilePath = "users.ser";
        database = new Database();
        activeClients = new ArrayList<>();
    }

    private boolean connectServer() {
        try {
            serverSocket = new ServerSocket(portNumber);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private boolean saveUserDatabase() {
        return database.exportToFile(userDatabaseFilePath, fileEncryptionKey);
    }

    private boolean loadUserDatabase() {
        return database.loadDatabase(userDatabaseFilePath, fileEncryptionKey);
    }

    private void initDatabase() {
        database.initDatabase();

        ArrayList<String[]> data = database.getUsersDatabase();
    }

    private boolean generateServerKeys() {
        //System.out.println("Going to generate new keys");
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
            return false;
        }
    }

    private boolean exportPrivateKeyToFile(String filePath) {
        try {
            //Get encryption key based on text
            byte[] input = privateKey.getEncoded();
            //System.out.println("Key len=" + input.length);
            byte[] fileEncryptionKeyBytes = fileEncryptionKey.getBytes("UTF-8");

            //Get 128 bit private encryption key from the given string
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            fileEncryptionKeyBytes = sha.digest(fileEncryptionKeyBytes);
            fileEncryptionKeyBytes = Arrays.copyOf(fileEncryptionKeyBytes, 16); // use only first 128 bit

            SecretKeySpec key = new SecretKeySpec(fileEncryptionKeyBytes, "AES");
            Cipher cipherPrivate = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
            cipherPrivate.init(Cipher.ENCRYPT_MODE, key);

            //Actually encrypt the content in the file
            CipherOutputStream cipherOutputStream = new CipherOutputStream(new FileOutputStream(filePath),
                                                                           cipherPrivate);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(cipherOutputStream);
            objectOutputStream.writeObject(privateKey);
            objectOutputStream.close();
            return true;
        } catch(IOException | NoSuchPaddingException| NoSuchAlgorithmException | InvalidKeyException |
                NoSuchProviderException e) {
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

    public ObjectStreamBundle sendNewKey(ObjectStreamBundle streams, Socket socket) {
        SecretKey newSessionKey = generateSessionKey();
        activeClients.remove(streams.outputStream);

        try {
            //Send the new session key
            PackageBundleObject packageBundleObject = new PackageBundleObject(null, newSessionKey);
            streams.outputStream.writeObject(packageBundleObject);
            streams.outputStream.flush();

            //Send initial iv
            //System.out.println("Going to send initial IV");
            Cipher outputCipher = initCipher(Cipher.ENCRYPT_MODE, newSessionKey, sessionKeyAlgorithm, null);
            if (outputCipher == null)
                return null;
            streams.outputStream.writeObject(outputCipher.getIV());
            streams.outputStream.flush();
            //System.out.println("Sent initial IV");

            //Receive initial iv
            //System.out.println("Going to receive initial IV");
            byte [] inputIV = (byte[])streams.inputStream.readObject();
            Cipher inputCipher = initCipher(Cipher.DECRYPT_MODE, newSessionKey, sessionKeyAlgorithm, inputIV);
            //System.out.println("Received initial IV");

            //Creating the real communications stream:
            //CLOSE THE SOCKET AND CONNECT TO THE CLIENT'S SERVER SOCKET, RETURNING THE CORRESPONDENT OBJECTSTREAMBUNDLE

            //Save client's location
            String clientLocation = socket.getInetAddress().getHostAddress();

            //Close the socket and connect to the client's server socket
            socket.close();
            socket = new Socket(clientLocation, portNumber2);

            CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), outputCipher);
            ObjectOutputStream outputStream = new ObjectOutputStream(cipherOutputStream);
            outputStream.flush(); activeClients.add(outputStream);
            CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), inputCipher);
            ObjectInputStream inputStream = new ObjectInputStream(cipherInputStream);
            //System.out.println("Created input stream with success!");

            return new ObjectStreamBundle(inputStream, outputStream);

        } catch (IOException | NoSuchAlgorithmException | ClassNotFoundException | InvalidKeyException |
                NoSuchPaddingException | NoSuchProviderException e) {
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
            CipherInputStream cipherInputStream = new CipherInputStream(new FileInputStream(privateKeyFilePath),
                                                                        cipherPrivate);
            ObjectInput objectInputStream = new ObjectInputStream(cipherInputStream);
            privateKey = (PrivateKey) objectInputStream.readObject();
            objectInputStream.close();
            return true;
        }catch (IOException | NoSuchPaddingException| NoSuchAlgorithmException | InvalidKeyException |
                NoSuchProviderException | ClassNotFoundException e) {
            return false;
        }
    }

    private boolean loadKeys() {
        return loadPublicKeyFromFile() && loadPrivateKeyFromFile();
    }


    public boolean sendPublicKeyToClient(Socket socket) {
        try {
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(publicKey);
            objectOutputStream.flush();
            return true;
        } catch (IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    public String handleUserAuthentication(ObjectStreamBundle streams) {
        boolean result;

        try {
            //Read user information
            ConnectionRequestObject connectionRequestObject = (ConnectionRequestObject) streams.inputStream.readObject();

            //Check username and password hash
            if (connectionRequestObject == null) {
                //System.out.println("Invalid object!");
                return null;
            }
            else if (connectionRequestObject.username == null || connectionRequestObject.usernameHash == null ||
                !connectionRequestObject.usernameHash.equals(DigestUtils.sha1Hex(connectionRequestObject.username))) {
                //System.out.println("Invalid username/hash!");
                return null;
            } else if (connectionRequestObject.password == null || connectionRequestObject.passwordHash == null ||
                      !connectionRequestObject.passwordHash.equals(DigestUtils.sha1Hex(connectionRequestObject.password))) {
                //System.out.println("Invalid password/hash!");
                return null;
            }

            result = lookupUser(connectionRequestObject.username, connectionRequestObject.password);
            //System.out.println("User tried to login with credentials " + connectionRequestObject.username + " " +
            //                    connectionRequestObject.password + " and got login result: " + result);

            //Send result to the user
            PackageBundleObject packageBundleObject = new PackageBundleObject("OK", null);
            streams.outputStream.writeObject(packageBundleObject);
            streams.outputStream.flush();
            return connectionRequestObject.username;
        } catch (ClassNotFoundException | IOException e) {
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    private boolean lookupUser(String username,String password) {
        return database.lookupUser(username, password);
    }

    private Cipher initCipher(int mode, Key key, String method, byte[] iv) throws InvalidKeyException,
                                                                                  NoSuchPaddingException,
                                                                                  NoSuchAlgorithmException,
                                                                                  NoSuchProviderException {
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

    public String readMessage(ObjectInputStream stream) {
        try {
            PackageBundleObject received = (PackageBundleObject) stream.readObject();

            if (received.message == null)
                return null;

            //Get message and compute its hash
            String messageHash = DigestUtils.sha1Hex(received.message);
            if (!messageHash.equals(received.messageHash)) {
                //System.out.println("Message has been tampered!");
                return null;
            }

            return received.message;
        } catch (IOException | ClassNotFoundException e){
            return null;
        }
    }

    public boolean sendMessage(String message, ObjectOutputStream ownerStream) {
        try{
            //Message hash and check if we need to change the key
            PackageBundleObject packageBundleObject = new PackageBundleObject(message, null);
            for(ObjectOutputStream stream : activeClients){
                if(stream != ownerStream){
                    //System.out.println("Going to send to the client " + packageBundleObject.message);
                    stream.writeObject(packageBundleObject);
                    stream.flush();
                }
            }

            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public void disconnect(ObjectStreamBundle streams){
        activeClients.remove(streams.outputStream);
        try {
            streams.outputStream.close();
            streams.inputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public boolean sendMessage(String message, ObjectOutputStream stream, SecretKey sessionKey) {
        try{
            PackageBundleObject packageBundleObject = new PackageBundleObject(message, sessionKey);
            stream.writeObject(packageBundleObject);
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
            if (rsaCipher == null)
                return null;
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            SessionKeyObject sessionKeyObject = (SessionKeyObject) objectInputStream.readObject();

            if (sessionKeyObject == null || sessionKeyObject.sessionKeyEncrypted == null || sessionKeyObject.sessionKeyhash == null) {
                //System.out.println("Failed to get session key!");
                return null;
            }

            byte[] sessionKeyEncoded = rsaCipher.doFinal(sessionKeyObject.sessionKeyEncrypted);
            //Check hash
            if (!sessionKeyObject.sessionKeyhash.equals(DigestUtils.sha1Hex(sessionKeyEncoded))) {
                //System.out.println("Failed to get session key!");
                return null;
            }

            SecretKey sessionKey =  new SecretKeySpec(sessionKeyEncoded, 0, sessionKeyEncoded.length, "AES") ;
            //System.out.println("Received client's session key " + sessionKey);

            //Receiving the initial IV for the input cypher
            byte [] inputIV = (byte[])objectInputStream.readObject();
            Cipher inputCipher = initCipher(Cipher.DECRYPT_MODE, sessionKey, sessionKeyAlgorithm, inputIV);

            //Sending the initial IV of the output cipher
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            Cipher outputCipher = initCipher(Cipher.ENCRYPT_MODE, sessionKey, sessionKeyAlgorithm, null);
            if (outputCipher == null)
                return null;
            objectOutputStream.writeObject(outputCipher.getIV());
            objectOutputStream.flush();

            //Creating the real communications stream
            CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), outputCipher);
            ObjectOutputStream outputStream = new ObjectOutputStream(cipherOutputStream);
            activeClients.add(outputStream); outputStream.flush();
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

    private void run() {
        while (true) {
            //System.out.println("Listening on socket on port " + portNumber +  "...");
            try {
                //Get new connection
                Socket socket = serverSocket.accept();

                //Create thread to deal with the client and start it
                ServerThread clientThread = new ServerThread(this, socket);
                clientThread.start();
            } catch (IOException e) {
                System.out.println("Error connecting to client...");
            }
        }
    }

    public static void main(String[] args) {
        //Add Bouncy Castle as Provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        Server server = new Server();

        /*Load Server's Public and Private Keys from disk*/
        if (!server.loadKeys()) {
            //System.out.println("No Key, going to generate");
            if (!server.generateServerKeys()) {
                System.out.println("Could not generate the server's private and public keys!");
                System.exit(-1);
            }
        }

        //Load database
        if (!server.loadUserDatabase()) {
            System.out.println("Could not load user database!Using default database!");
            server.initDatabase();
            server.saveUserDatabase();
        }

        if (server.connectServer()) {
            server.run();
        }
        else{
            System.out.println("Could not connect to server or load certificate factory!");
            System.exit(-1);
        }

    }

    public class ObjectStreamBundle {
        public ObjectOutputStream outputStream;
        public ObjectInputStream inputStream;

        public ObjectStreamBundle(ObjectInputStream in, ObjectOutputStream out) {
            inputStream = in;
            outputStream = out;
        }
    }
}
