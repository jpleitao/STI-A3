package test;

import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class Client {

    private int portNumber;
    private String publicKeyFilePath;
    private String host;
    private Key serverPublicKey;
    private Key communicationKey; //The session key
    private Socket socket;
    private Cipher cipher;

    public Client() {
        portNumber = 9996;
        host = "localhost";
        publicKeyFilePath = "/home/joaquim/Desktop/publickey.ser";
    }

    private void connectToServer() throws IOException {
        socket = new Socket(host, portNumber);
    }

    private void getPublicKeyFromFile() throws IOException, ClassNotFoundException {
        FileInputStream fileInputStream = null;

        fileInputStream = new FileInputStream(publicKeyFilePath);
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        serverPublicKey = (Key) objectInputStream.readObject();
    }

    private void initCipher(int mode, Key key) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException {
        cipher = Cipher.getInstance("RSA");
        cipher.init(mode, key);
    }

    private String readMessage() throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IOException {
        initCipher(Cipher.DECRYPT_MODE, communicationKey);

        CipherInputStream cipherInputStream = new CipherInputStream(socket.getInputStream(), cipher);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(cipherInputStream));

        return bufferedReader.readLine();
    }

    private void sendMessage(String message) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IOException {
        initCipher(Cipher.ENCRYPT_MODE, serverPublicKey);

        CipherOutputStream cipherOutputStream = new CipherOutputStream(socket.getOutputStream(), cipher);
        PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(cipherOutputStream));

        System.out.println("Vou enviar " + message);
        printWriter.write(message);
        printWriter.close();
    }

    public static void main(String[] args) {

        String message = "OLA";

        try {

            Client client = new Client();

            client.getPublicKeyFromFile();
            client.connectToServer();

            client.sendMessage(message);

        } catch(IOException ioe) {
            ioe.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
