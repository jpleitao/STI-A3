package common;

import java.io.Serializable;

public class ConnectionRequestObject implements Serializable{

    public String username;
    public String password;

    public ConnectionRequestObject(String user, String pass) {
        username = user;
        password = pass;
    }
}
