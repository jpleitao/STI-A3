package common;

import org.apache.commons.codec.digest.DigestUtils;

import java.io.Serializable;

public class ConnectionRequestObject implements Serializable{

    public String username;
    public String password;
    public String usernameHash;
    public String passwordHash;

    public ConnectionRequestObject(String user, String pass) {
        username = user;
        password = pass;
        usernameHash = DigestUtils.sha1Hex(username);
        passwordHash = DigestUtils.sha1Hex(password);
    }
}
