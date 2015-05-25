package common;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CertificateBundleObject implements Serializable{

    public X509Certificate certificate;
    public PrivateKey privateKey;


    public CertificateBundleObject(X509Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }
}
