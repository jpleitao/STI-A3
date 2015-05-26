package common;

import org.apache.commons.codec.digest.DigestUtils;
import java.io.Serializable;

public class SessionKeyObject implements Serializable {

    public byte[] sessionKeyEncrypted;
    public String sessionKeyhash;


    public SessionKeyObject(byte[] keyEncrypted, byte[] sessionKeyEncoded) {
        sessionKeyEncrypted = keyEncrypted;
        sessionKeyhash = DigestUtils.sha1Hex(sessionKeyEncoded);
    }
}
