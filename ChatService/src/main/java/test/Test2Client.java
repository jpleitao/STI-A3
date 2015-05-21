package test;


import org.bouncycastle.openssl.PEMReader;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.Certificate;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

public class Test2Client {

    public static void main(String[] args) {
        String certificateFile = "/home/joaquim/Desktop/certificateClient.cer";
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
        }

    }
}
