package ca;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CA {

    private final int port;
    private final long rootCertificateDuration;
    private final String rootCertificateLocation;
    private final String publicKeyLocation;

    private ServerSocket serverSocket;
    private KeyPair keyPair;
    private CertAndKeyGen keyGen;
    private X509Certificate rootCertificate;

    public CA(){
        serverSocket = null;
        port = 6000;
        rootCertificateDuration = (long) 365 * 24 * 60 * 60;
        publicKeyLocation = "CA-PublicKey.ser";
        rootCertificateLocation = "CA-Certificate.ser";
        rootCertificate = null;
        try {
            serverSocket = new ServerSocket(port);
            keyGen = new CertAndKeyGen("RSA","SHA1WithRSA", null);
        } catch(IOException ioexception) {
            System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
            serverSocket = null;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            keyGen = null;
        }
    }

    public void run() {
        while (true) {
            System.out.println("Listening on socket on port " + port +  "...");
            try {
                //Get new connection
                Socket socket = serverSocket.accept();
                //Create client thread and start it
                CAThread caThread = new CAThread(socket, rootCertificate, keyPair.getPrivate());
                caThread.start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private boolean generateAndSaveKeys() {
        try {
            keyGen.generate(1024);
            keyPair = new KeyPair(keyGen.getPublicKey(), keyGen.getPrivateKey());
            return savePublicKey();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            System.out.println("Error generating public and private Keys!");
            return false;
        }
    }

    private boolean savePublicKey() {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(publicKeyLocation));
            oos.writeObject(keyPair.getPublic());
            oos.close();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Error saving public Key");
            return false;
        }
    }

    private boolean generateAndSaveRootCertificate() {
        try {
            rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT"), rootCertificateDuration);
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(rootCertificateLocation));
            oos.writeObject(rootCertificate);
            oos.close();
            return true;
        } catch (CertificateException | InvalidKeyException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException | IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean getStatus() {
        return serverSocket != null;
    }

    public static void main(String args[]) {
        boolean result;
        CA ca = new CA();

        //Generate CA public-private Key and store it in a file
        result = ca.generateAndSaveKeys();
        if (result)
        {
            //Generate Root Certificate and store it in a file
            result = ca.generateAndSaveRootCertificate();
            if (result && ca.getStatus())
                ca.run();
        }

    }
}
