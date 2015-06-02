package server;

import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;

public class Database {

    private ArrayList<String[]> usersDatabase;

    public Database() {
        usersDatabase = new ArrayList<>();
    }

    public Database(String filePath, String fileEncryptionKey) {
        usersDatabase = new ArrayList<>();
        loadDatabase(filePath, fileEncryptionKey);
    }

    public ArrayList<String[]> getUsersDatabase() {
        return usersDatabase;
    }

    public boolean lookupUser(String username, String password) {
        String[] current;
        for (String[] anUsersDatabase : usersDatabase) {
            current = anUsersDatabase;
            if (current[0].equals(username) && current[1].equals(password))
                return true;
        }

        return false;
    }

    public void initDatabase() {
        usersDatabase.add(new String[] {"joaquim", DigestUtils.sha1Hex("1234")});
        usersDatabase.add(new String[] {"andre", DigestUtils.sha1Hex("4321")});
        usersDatabase.add(new String[] {"joao", DigestUtils.sha1Hex("coimbra")});
        usersDatabase.add(new String[] {"jorge", DigestUtils.sha1Hex("uc")});
    }

    public boolean exportToFile(String filePath, String fileEncryptionKey) {
        try {
            byte[] fileEncryptionKeyBytes = fileEncryptionKey.getBytes("UTF-8");
            //Get 128 bit private encryption key from the given string
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            fileEncryptionKeyBytes = sha.digest(fileEncryptionKeyBytes);
            fileEncryptionKeyBytes = Arrays.copyOf(fileEncryptionKeyBytes, 16); // use only first 128 bit

            SecretKeySpec key = new SecretKeySpec(fileEncryptionKeyBytes, "AES");
            Cipher cipherPrivate = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
            cipherPrivate.init(Cipher.ENCRYPT_MODE, key);

            //Actually encrypt the content in the file
            CipherOutputStream cipherOutputStream = new CipherOutputStream(new FileOutputStream(filePath),
                    cipherPrivate);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(cipherOutputStream);
            objectOutputStream.writeObject(usersDatabase);
            objectOutputStream.close();
            return true;
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException |
                InvalidKeyException e) {
            return false;
        }
    }

    public boolean loadDatabase(String filePath, String fileEncryptionKey) {
        try{
            //Get decryption key based on text
            byte[] fileEncryptionKeyBytes = fileEncryptionKey.getBytes("UTF-8");
            //Get 128 bit private encryption key from the given string
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            fileEncryptionKeyBytes = sha.digest(fileEncryptionKeyBytes);
            fileEncryptionKeyBytes = Arrays.copyOf(fileEncryptionKeyBytes, 16); // use only first 128 bits

            SecretKeySpec key = new SecretKeySpec(fileEncryptionKeyBytes, "AES");
            Cipher cipherPrivate = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
            cipherPrivate.init(Cipher.DECRYPT_MODE, key);

            //Actually decrypt the content in the file
            CipherInputStream cipherInputStream = new CipherInputStream(new FileInputStream(filePath), cipherPrivate);
            ObjectInput objectInputStream = new ObjectInputStream(cipherInputStream);
            usersDatabase = (ArrayList<String[]>) objectInputStream.readObject();
            objectInputStream.close();
            return true;
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException |
                InvalidKeyException | ClassNotFoundException e) {
            return false;
        }
    }
}
