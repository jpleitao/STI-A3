package test;


import org.bouncycastle.openssl.PEMReader;

import java.io.*;
import java.security.Certificate;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Test2Client {

    public static void main(String[] args) {
        String certificateFile = "/home/joaquim/Desktop/certificateClient.cer";
        /*
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        try{
            FileReader fr = new FileReader(certificateFile);
            PEMReader pemReader = new PEMReader(fr);

            X509Certificate cert = (X509Certificate)pemReader.readObject();
            System.out.println(cert);
            PublicKey pk = cert.getPublicKey();
            System.out.println(pk);
        } catch(FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }*/

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            System.out.println();
            System.out.println("CertificateFactory Object Info: ");
            System.out.println("Type = " + cf.getType());
            System.out.println("Provider = " + cf.getProvider());
            System.out.println("toString = " + cf.toString());

            FileInputStream fis = new FileInputStream(certificateFile);
            java.security.cert.Certificate cert = cf.generateCertificate(fis);
            fis.close();
            System.out.println();
            System.out.println("Certificate Object Info: ");
            System.out.println("Type = " + cert.getType());
            System.out.println("toString = " + cert.toString());

            PublicKey pubKey = cert.getPublicKey();
            System.out.println();
            System.out.println("PublicKey Object Info: ");
            System.out.println("Algorithm = " + pubKey.getAlgorithm());
            System.out.println("Format = " + pubKey.getFormat());
            System.out.println("toString = " + pubKey.toString());
        } catch(CertificateException c){
            c.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
