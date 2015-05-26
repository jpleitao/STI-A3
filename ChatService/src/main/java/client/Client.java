package client;

import common.ConnectionRequestObject;
import common.PackageBundleObject;
import common.SessionKeyObject;
import org.apache.commons.codec.digest.DigestUtils;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;

public class Client{

    private final int portNumber;
    private final int portNumber2;
    private final String serverHost;
    private final String sessionKeyAlgorithm;
    private final String serverEncryptionAlgorithm;
    private final int SESSIONKEYSIZE;

    private SecureRandom secureRandom;
    private Key serverPublicKey;
    private SecretKey communicationKey; //The session key
    private Socket socket;
    private ObjectInputStream inputStream;
    private ObjectOutputStream outputStream;
    private ClientThread clientThread;
    private String username;
    private String password;
    private BufferedReader console;
    private int counter=0;

    public Client(String username, String password) {
        portNumber = 9996;
        portNumber2 = 9997;
        SESSIONKEYSIZE = 128;
        serverHost = "localhost";
        sessionKeyAlgorithm = "AES/CFB8/NoPadding";
        serverEncryptionAlgorithm = "RSA/None/PKCS1Padding";
        serverPublicKey = null;
        communicationKey = null;
        socket = null;
        secureRandom = new SecureRandom();
        clientThread = null;
        this.username = username;
        this.password = password;
        console = new BufferedReader(new InputStreamReader(System.in));
    }

    private boolean connectToServer() {
        try {
            socket = new Socket(serverHost, portNumber);

            //Get server public key
            System.out.println("Going to get the server's public key");
            if(!getServerPublicKey()) {
                System.out.println("Could not get server's public key");
                return false;
            }

            //Generate communication key
            communicationKey = generateSessionKey();
            //Send communication key to server
            if (!sendSessionKey()) {
                System.out.println("Could not establish a session with the server");
                return false;
            }

            /* Send user credentials over secure connection
             * Since the server is giving us a response we can assure that the server got the message and the session
             * key, so is there any need for further server authentication? FIXME
             */
            if(!authenticateUser()) {
                System.out.println("Failed to log in");
                return false;
            }

            return true;
        } catch(IOException ioexception) {
            ioexception.printStackTrace();
            return false;
        }
    }

    public void run(){
        sendMessage("ola");

        /*
        int i=0;
        while (i<1){
            try {
                String line = console.readLine();
                sendMessage(line);

            }catch (IOException e) {
                e.getMessage();
                e.printStackTrace();
            }
            i++;
        }*/

    }

    private boolean getServerPublicKey() {

        try {
            //Send the server a boolean value to inform of the client's need to get its public key
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
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

    private boolean checkHash(SecretKey newSessionKey, String newSessionKeyHash) {

        //Confirm the hash
        String hash = DigestUtils.sha1Hex(newSessionKey.getEncoded());
        if (!hash.equals(newSessionKeyHash))
            return false;

        try{

            //Receiving the initial IV for the input cypher
            byte [] inputIV = (byte[])inputStream.readObject();
            Cipher inputCipher = initCipher(Cipher.DECRYPT_MODE, newSessionKey, sessionKeyAlgorithm, inputIV);

            //Sending the initial IV of the output cipher
            Cipher outputCipher = initCipher(Cipher.ENCRYPT_MODE, newSessionKey, sessionKeyAlgorithm, null);
            if (outputCipher == null)
                return false;
            outputStream.writeObject(outputCipher.getIV());
            outputStream.flush();

            //Create new Input and Output Stream:
            //CLOSE THE CONNECTION AND OPEN A SERVER SOCKET, WAITING FOR THE SERVER CONNECTION

            //Close the socket
            socket.close();

            //Wait for the server connection!
            ServerSocket serverSocket = new ServerSocket(portNumber2);
            socket = serverSocket.accept();
            serverSocket.close();

            CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), outputCipher);
            outputStream = new ObjectOutputStream(cipherOutputStream);
            outputStream.flush();
            CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), inputCipher);
            inputStream = new ObjectInputStream(cipherInputStream);
            return true;
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException |
                ClassNotFoundException | InvalidKeyException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }

    }

    public boolean sendMessage(String message) {
        counter++;
        try{
            PackageBundleObject packageBundleObject = new PackageBundleObject(message, null);
            outputStream.writeObject(packageBundleObject);
            outputStream.flush();

            System.out.println("Counter: " +counter);
            return true;
        } catch (IOException e) {
            e.getMessage();
            e.printStackTrace();

            System.out.println("Counter: " +counter);
            return false;
        }
    }

    public String readMessage() {
        try {
            PackageBundleObject received = (PackageBundleObject) inputStream.readObject();

            System.out.println("RECEBI " + received.message + " " + received.newSessionKey);

            //Get message and compute its hash
            if (received.message != null) {
                String messageHash = DigestUtils.sha1Hex(received.message);
                if (!messageHash.equals(received.messageHash)) {
                    System.out.println("Message has been tampered!");
                    return null;
                }
                return received.message;
            }

            //Check if we have session key
            else if (received.newSessionKey != null) {
                System.out.println("Got new Session Key!");
                //Confirm the hash and updates the input and output streams
                if (!checkHash(received.newSessionKey, received.newSessionKeyHash)) {
                    System.out.println("New Session Key has been tampered");
                    return null;
                }
                return "";
            }
            return null;
        } catch (IOException|ClassNotFoundException e){
            //e.getMessage();
            //e.printStackTrace();
            return null;
        }
    }

    private boolean sendSessionKey() {
        try{
            //Encrypt the request with the server's public key
            Cipher rsaCipher = initCipher(Cipher.ENCRYPT_MODE, serverPublicKey, serverEncryptionAlgorithm, null);
            if (rsaCipher == null)
                return false;
            byte [] sessionKeyEncripted = rsaCipher.doFinal(communicationKey.getEncoded());

            SessionKeyObject sessionKeyObject = new SessionKeyObject(sessionKeyEncripted, communicationKey.getEncoded());

            //Sending the session key encrypted
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(sessionKeyObject);
            objectOutputStream.flush();
            System.out.println("Sent sessionKey encrypted with Server's public key");

            //Sending the initial IV of the output cipher
            Cipher outputCipher = initCipher(Cipher.ENCRYPT_MODE, communicationKey, sessionKeyAlgorithm, null);
            if (outputCipher == null)
                return false;
            objectOutputStream.writeObject(outputCipher.getIV());
            objectOutputStream.flush();

            //Receiving the initial IV for the input cypher
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            byte [] inputIV = (byte[])objectInputStream.readObject();
            Cipher inputCipher = initCipher(Cipher.DECRYPT_MODE, communicationKey, sessionKeyAlgorithm, inputIV);

            //Creating the real communications stream
            CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), outputCipher);
            outputStream = new ObjectOutputStream(cipherOutputStream);
            outputStream.flush();
            CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), inputCipher);
            inputStream = new ObjectInputStream(cipherInputStream);
            return true;
        } catch (IllegalBlockSizeException | BadPaddingException | IOException | InvalidKeyException |
                 NoSuchPaddingException | NoSuchProviderException |NoSuchAlgorithmException | ClassNotFoundException e){
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private boolean authenticateUser() {
        try{
            //Create the object with the request
            ConnectionRequestObject connectionRequestObject = new ConnectionRequestObject(username, password);
            //Send the user information
            outputStream.writeObject(connectionRequestObject);
            outputStream.flush();

            //Receive the feedback
            PackageBundleObject result = (PackageBundleObject) inputStream.readObject();
            //Check hash
            if (result == null || result.message == null || result.messageHash == null || !result.messageHash.equals(DigestUtils.sha1Hex(result.message))) {
                System.out.println("Invalid confirmation message hash!");
                return false;
            }
            System.out.println("Got authentication result: " + result.message);
            return result.message.equals("OK");
        } catch(IOException | ClassNotFoundException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    private void startClientThread() {
        clientThread = new ClientThread(this);

        clientThread.start();
    }

    public static void main(String[] args) {
        //Call it Magic: Add Bouncy Castle as Provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        Client client;
        if (args.length != 2)
            client = new Client("joaquim", "1234");
        else
            //Create the client and connect it to the Chat Server
            client = new Client(args[0], args[1]);

        if (client.connectToServer()) {
            System.out.println("Connected! Going to start client thread!");
            //Create Client Thread
            client.startClientThread();
            client.run();
        }
    }
}
