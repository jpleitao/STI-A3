package client;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Client {

    private final int portNumber;
    private final String serverPublicKeyFilePath;
    private final String serverHost;
    private final String sessionKeyAlgorithm;

    private Key serverPublicKey;
    private SecretKey communicationKey; //The session key
    private Socket socket;
    private Cipher cipher;
    private X509Certificate certificate;
    private String name;

    public Client(String name) {
        portNumber = 9996;
        serverPublicKeyFilePath = "Server-PublicKey.ser";
        serverHost = "localhost";
        sessionKeyAlgorithm = "AES";
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
            return receiveSessionKey();
        } catch(IOException ioexception) {
            ioexception.printStackTrace();
            return false;
        }
    }

    private Key getCurrentKeyEncryption(){
        if (communicationKey == null)
        {
            System.out.println("Going to encrypt with server's public key");
            return serverPublicKey;
        }
        System.out.println("Going to encrypt with communicationKey");
        return communicationKey;
        //return communicationKey==null?serverPublicKey:communicationKey;
    }

    private Key getCurrentKeyDecryption(){
        //FIXME: THIS MAY NEED TO BE CHANGED IF WE ADD A PUBLIC-PRIVATE KEY TO THE CLIENT
        return communicationKey==null?serverPublicKey:communicationKey;
    }

    private boolean receiveSessionKey() {
        byte[] encodedKey = readMessage();
        if (encodedKey == null)
            return false;
        communicationKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, sessionKeyAlgorithm);
        System.out.println(communicationKey);
        return true;
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

    private void initCipher(int mode, Key key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        cipher = Cipher.getInstance("RSA");
        cipher.init(mode, key);
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

    private byte[] decryptMessage(byte[] message) {
        try{
            initCipher(Cipher.DECRYPT_MODE, getCurrentKeyDecryption());

            byte[] decrypted = new byte[cipher.getOutputSize(message.length)];
            int dec_len = cipher.update(message, 0, message.length, decrypted, 0);
            cipher.doFinal(decrypted, dec_len);
            decrypted = filterMessage(decrypted);
            return decrypted;
        } catch(BadPaddingException | IllegalBlockSizeException | ShortBufferException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e){
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    private byte[] readMessage() {
        try {
            byte[] data = new byte[socket.getReceiveBufferSize()];
            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            int received = dataInputStream.read(data);
            byte[] decryptedData = decryptMessage(data);
            System.out.println("Got data " + Arrays.toString(decryptedData));
            return decryptedData;
        } catch (IOException e) {
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    private byte[] encryptMessage(byte[] message) {
        try {
            initCipher(Cipher.ENCRYPT_MODE, getCurrentKeyEncryption());
            byte[] encrypted = new byte[cipher.getOutputSize(message.length)];
            int enc_len = cipher.update(message, 0, message.length, encrypted, 0);
            cipher.doFinal(encrypted, enc_len);
            return encrypted;
        } catch(BadPaddingException | IllegalBlockSizeException | ShortBufferException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.getMessage();
            e.printStackTrace();
            return null;
        }
    }

    private boolean sendMessage(byte[] message) {
        try {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

            System.out.println("O tamamho da mensagem e de " + message.length);
            System.out.println("Mensagem Antes da Encriptaçao " + Arrays.toString(message));

            byte[] messageEncrypted = encryptMessage(message);
            if (messageEncrypted == null)
                return false;
            System.out.println("Mensagem Encriptada " + Arrays.toString(messageEncrypted));
            System.out.println("O len e " + messageEncrypted.length);
            dataOutputStream.write(messageEncrypted, 0, messageEncrypted.length);
            return true;
        } catch (IOException e) {
            e.getMessage();
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Invalid arguments! Please call: java CAClient <Client-Name>");
            return ;
        }
        //Create the client and connect it to the Chat Server
        Client client = new Client(args[0]);
        if (!client.loadStuff()) {
            System.out.println("Could not load the client's certificate or the server's public key. Please try again later...");
            System.exit(1);
        }
        if (client.connectToServer())
            System.out.println("lolitos");
    }
}
