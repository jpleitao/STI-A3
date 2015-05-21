package test;

import org.bouncycastle.openssl.PEMReader;

import javax.crypto.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Server {

    private int portNumber;
    private String publicKeyFilePath;
    private KeyPair keyPair;
    private ServerSocket serverSocket;
    private Cipher cipher;
    private CertificateFactory certificateFactory;

    private static final int KEYSIZE = 512;

    public Server() throws NoSuchAlgorithmException, IOException, CertificateException {
        portNumber = 9996;
        publicKeyFilePath = "/home/joaquim/Desktop/publickey.ser";
        keyPair = generateKeyPair();
        serverSocket = new ServerSocket(portNumber);
        certificateFactory = CertificateFactory.getInstance("X.509");
    }

    public Server(int port, String publicKeyFile) throws NoSuchAlgorithmException, IOException, CertificateException {
        portNumber = port;
        publicKeyFilePath = publicKeyFile;
        keyPair = generateKeyPair();
        serverSocket = new ServerSocket(portNumber);
        certificateFactory = CertificateFactory.getInstance("X.509");
    }

    private StringBuffer convertKeyToString(Key key) {
        byte[] keyEncode = key.getEncoded();
        StringBuffer retString = new StringBuffer();
        for (byte aKeyEncode : keyEncode) {
            retString.append(Integer.toHexString(0x0100 + (aKeyEncode & 0x00FF)).substring(1));
        }
        return retString;
    }

    private void exportKeyToFile(Key key, String filePath) {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath));
            oos.writeObject(key);
        } catch(IOException ioe) {
            ioe.printStackTrace();
        }
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(KEYSIZE);
        return keyGen.genKeyPair();
    }

    public Key getPublicKey() {
        return keyPair.getPublic();
    }

    private Key getPrivateKey() {
        return keyPair.getPrivate();
    }

    public String getPublicKeyFilePath() {
        return publicKeyFilePath;
    }

    public ServerSocket getServerSocket() {
        return serverSocket;
    }

    private void initCipher(int mode, Key key) throws InvalidKeyException, NoSuchPaddingException,
                                                     NoSuchAlgorithmException {
        cipher = Cipher.getInstance("RSA");
        cipher.init(mode, key);
    }

    private String readMessage(Socket socket) throws NoSuchPaddingException, NoSuchAlgorithmException,
                                                     InvalidKeyException, IOException {
        initCipher(Cipher.DECRYPT_MODE, getPrivateKey());

        CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), cipher);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(cipherInputStream));

        return bufferedReader.readLine();
    }

    private void sendMessage(String message, Socket socket) throws NoSuchPaddingException, NoSuchAlgorithmException,
                                                                   InvalidKeyException, IOException {
        initCipher(Cipher.ENCRYPT_MODE, getPublicKey());//FIXME: Replace this key with the session key to the given client!

        CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), cipher);
        PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(cipherOutputStream));
        DataOutputStream dataOutputStream = new DataOutputStream(cipherOutputStream);

        System.out.println("Vou enviar " + message);
        printWriter.write(message);
        printWriter.close();
    }

    public static void main(String[] args) {

        try{
            Server server = new Server();

            //Export PublicKey to File
            server.exportKeyToFile(server.getPublicKey(), server.getPublicKeyFilePath());

            //In the real thing this would not be like this, but then again we do not have to implement this part!
            Socket clientSocket = server.getServerSocket().accept();

            String data = server.readMessage(clientSocket);

            System.out.println("Recebi " + data);

            server.sendMessage("ADEUS", clientSocket);

        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }
}


