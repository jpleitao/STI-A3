package common;

import org.apache.commons.codec.digest.DigestUtils;
import javax.crypto.SecretKey;
import java.io.Serializable;

public class PackageBundleObject implements Serializable{

    public String message;
    public String messageHash;
    public SecretKey newSessionKey;
    public String newSessionKeyHash;

    public PackageBundleObject(String message, SecretKey newSessionKey) {
        this.message = message;
        this.newSessionKey = newSessionKey;
        if (message != null)
            this.messageHash = DigestUtils.sha1Hex(message);
        else
            this.messageHash = null;
        if (newSessionKey != null)
            this.newSessionKeyHash = DigestUtils.sha1Hex(newSessionKey.getEncoded());
        else
            this.newSessionKeyHash = null;
    }
}
