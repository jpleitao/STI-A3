package ca;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CAThread extends Thread {

    private Socket clientSocket;
    private DataInputStream dataInputStream;
    private ObjectOutputStream objectOutputStream;
    private final int certificateKeyLength = 1024;
    private X509Certificate caCertificate;
    private PrivateKey caPrivateKey;

    public CAThread(Socket clientSocket, X509Certificate caCertificate, PrivateKey caPrivateKey) {
        this.clientSocket = clientSocket;
        this.caCertificate = caCertificate;
        this.caPrivateKey = caPrivateKey;
        dataInputStream = null;
        objectOutputStream = null;
    }

    public void run()
    {
        try {
            dataInputStream = new DataInputStream(clientSocket.getInputStream());
            objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());

            //Receive name of the certificate and other relevant data
            String certitficateName = readMessageFromSocket();
            X509Certificate clientCertificate = generateCertificateLeaf(certitficateName);
            System.out.println("Generated certificate for Client");

            objectOutputStream.writeObject(clientCertificate);
            System.out.println("Sended Certificate to Client");
        } catch (IOException ioexception) {
            ioexception.printStackTrace();
            this.interrupt();
        }
        this.interrupt();
    }

    private String readMessageFromSocket() {
        try {

            return dataInputStream.readUTF();
        } catch (IOException e) {
            System.out.println("Error reading message from client " + e.getMessage());
            this.interrupt();
            return null;
        }
    }

    private X509Certificate generateCertificateLeaf(String cn) {
        try {
            CertAndKeyGen keyGen2 = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
            keyGen2.generate(certificateKeyLength);
            PrivateKey topPrivateKey = keyGen2.getPrivateKey();
            X509Certificate topCertificate = keyGen2.getSelfCertificate(new X500Name("CN=" + cn), (long) 365 * 24 * 60 * 60);
            topCertificate = createSignedCertificate(topCertificate, caCertificate, caPrivateKey);
            return topCertificate;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        return null;
    }

    private X509Certificate createSignedCertificate(X509Certificate cetrificate,X509Certificate issuerCertificate,PrivateKey issuerPrivateKey){
        try{
            Principal issuer = issuerCertificate.getSubjectDN();
            String issuerSigAlg = issuerCertificate.getSigAlgName();

            System.out.println("Algorithm: " + issuerSigAlg);

            byte[] inCertBytes = cetrificate.getTBSCertificate();
            X509CertInfo info = new X509CertInfo(inCertBytes);
            info.set(X509CertInfo.ISSUER, (X500Name) issuer);

            //No need to add the BasicContraint for leaf cert
            if(!cetrificate.getSubjectDN().getName().equals("CN=TOP")){
                CertificateExtensions exts=new CertificateExtensions();
                BasicConstraintsExtension bce = new BasicConstraintsExtension(true, -1);
                exts.set(BasicConstraintsExtension.NAME,new BasicConstraintsExtension(false, bce.getExtensionValue()));
                info.set(X509CertInfo.EXTENSIONS, exts);
            }

            X509CertImpl outCert = new X509CertImpl(info);
            outCert.sign(issuerPrivateKey, issuerSigAlg);

            return outCert;
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return null;
    }
}
