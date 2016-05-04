/*Author: Chris Brown
* Date: 01/05/2016
* Description: Program to...
* * store and write password protected files
* * decrypt password protected files
* * perform checks of password protected files
* */

import sun.misc.BASE64Decoder;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.*;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Scanner;

public class Protect {

    private final String PASSWORD_LIST_PATH = "Q1/Q1/passwords_list";

    public static void main(String[] args){
        Protect protect = new Protect();

        //What operation do we want to do?
        /* -e = encrypt
        * -d = decrypt
        * -c = check */
        if(args[0].equals("-e")){
            System.out.println("Encrypt");
            String filePath = args[1];
            String password = args[2];
            //Check filename and password are provided
            protect.checkFilePassInput(filePath, password);

            //Does the file exist?
            File f2Encrypt = new File(filePath);
            protect.checkFileExists(f2Encrypt);

            //Is it registered
            HashMap<String, Passwords> data = protect.getPasswordData();
            protect.checkIsRegistered(f2Encrypt.getName(), data);

            //Check the password
            if(password.equals(data.get(f2Encrypt.getName()).getWritePass())){
                //Correct password
                try{
                    //Get file bytes
                    InputStream inputStream = new FileInputStream(f2Encrypt);
                    byte[] buffer = new byte[(int) f2Encrypt.length()];
                    inputStream.read(buffer);
                    inputStream.close();

/*                    BASE64Decoder decoder = new BASE64Decoder();
//                    byte[] pk = decoder.decodeBuffer(password);
//                    byte[] sk = decoder.decodeBuffer(data.get(f2Encrypt.getName()).getReadPass());
                    byte[] pk = password.getBytes();
                    byte[] sk = data.get(f2Encrypt.getName()).getReadPass().getBytes();

                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
                    kpGen.initialize(1024, new SecureRandom(pk));
                    KeyPair kp = kpGen.generateKeyPair();

                    //Generate cipher
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
                    //Encrypt file
                    byte[] cipherText = cipher.doFinal(buffer);*/

                    Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    KeyGenerator keygen = KeyGenerator.getInstance("AES");
                    SecretKeySpec skSpec = new SecretKeySpec(buffer, "AES");
                    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("AES");
                    SecretKey aeskey = keyFactory.generateSecret(skSpec);
                    aesCipher.init(Cipher.ENCRYPT_MODE, aeskey);

                    byte[] cipherText = aesCipher.doFinal(buffer);

/*                    //Generate signature
                    Signature sign = Signature.getInstance("SHA256withRSA");
                    sign.initSign(kp.getPrivate());
                    sign.update(cipherText);
                    byte[] signature = sign.sign();*/

                    //Save encrypted file and signature
                    FileOutputStream outputStream = new FileOutputStream(filePath + ".enc");
                    outputStream.write(cipherText);
                    outputStream.close();

/*                    outputStream = new FileOutputStream(filePath + ".sign");
                    outputStream.write(signature);
                    outputStream.close();*/
                }
                catch(Exception e){
                    e.printStackTrace();
                }
                //TODO encrypt to filename.enc or overwrite filename.enc
                //TODO delete original filename
            }
            else{
                System.out.println("Incorrect write password");
                System.exit(1);
            }
        }
        else if(args[0].equals("-d")){
            System.out.println("Decrypt");
        }
        else if(args[0].equals("-c")){
            System.out.println("Check");
        }
        else{
            throw new IllegalArgumentException("Unknown option");
        }
    }

    private static void functionUsagePrompt(){
        System.out.println("java Protect [option] [filename] [password]");
    }

    private void checkFilePassInput(String filename, String password){
        if(filename == null){
            System.out.println("No file name given");
            Protect.functionUsagePrompt();
            System.exit(1);
        }
        else if(password == null){
            System.out.println("No password given");
            Protect.functionUsagePrompt();
            System.exit(1);
        }
    }

    private void checkFileExists(File file){
        if(!file.exists()){
            System.out.println("File: " + file.getName() + " does not exist");
            System.exit(1);
        }
    }

    private void checkIsRegistered(String filename, HashMap<String, Passwords> data){
        if(!data.containsKey(filename)){
            System.out.println("File is not registered");
            System.exit(1);
        }
    }

    private HashMap<String, Passwords> getPasswordData(){
        HashMap<String, Passwords> data = new HashMap<String, Passwords>();
        try{
            File passwordList = new File(PASSWORD_LIST_PATH);
            System.out.println(passwordList.getAbsolutePath());
            Scanner reader = new Scanner(passwordList);

            //Trim lines and add to data - Exclude titles
            reader.nextLine();
            while(reader.hasNext()){
                String passwordLine = reader.nextLine().trim();
                String[] lineData = passwordLine.split("\t");
                data.put(lineData[0], new Passwords(lineData[1],lineData[2]));
            }
        }
        catch(FileNotFoundException e){
            System.out.println("Password list not found");
        }
        return data;
    }

    private static class Passwords{
        private String readPass;
        private String writePass;

        private Passwords(String readPass, String writePass){
            this.readPass = readPass;
            this.writePass = writePass;
        }

        private String getReadPass() {
            return readPass;
        }

        private String getWritePass() {
            return writePass;
        }
    }
}
