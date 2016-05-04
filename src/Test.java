import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.HashMap;
import java.util.Scanner;

public class Test {

    private HashMap<String, ReadWritePasswords> readWritePwds;
    private final String outputDir = "Q1/Q1/";

    public static void main(String[] args){
        Test test = new Test();
        String op = args[0];
        test.readWritePwds = test.getPasswordData();
        String baseFileName;

        if(op.equals("-e")){
            String filename = args[1];
            String password = args[2];
            test.checkFilePassInput(filename, password);
            File f2Encrypt = new File(filename);
            baseFileName = stripExtension(f2Encrypt.getName());
            //Set security policy
            System.setSecurityManager(new WriteSecurityManager(baseFileName, password, test.readWritePwds));
            //Encrypt
            test.encrypt(f2Encrypt, test.readWritePwds.get(baseFileName).getReadPass());
        }
        else if(op.equals("-d")){
            String filename = args[1];
            String password = args[2];
            test.checkFilePassInput(filename, password);
            File f2Encrypt = new File(filename);
            baseFileName = stripExtension(f2Encrypt.getName());
            //Set security policy
            System.setSecurityManager(new ReadSecurityManager(baseFileName, password, test.readWritePwds));
            //Decrypt
            test.decrypt(filename);
        }
        else if(op.equals("-c")){
            //Check
            test.check();
        }
        else{
            throw new IllegalArgumentException("need -e, -d or -c");
        }
    }

    private void encrypt(File f2Encrypt, String keyPassword){
        String baseFileName = stripExtension(f2Encrypt.getName());
        checkIsRegistered(baseFileName, readWritePwds);

        try{
            //Get file bytes
            InputStream inputStream = new FileInputStream(f2Encrypt);
            byte[] inputBuffer = new byte[(int) f2Encrypt.length()];
            inputStream.read(inputBuffer);
            inputStream.close();

            //Generate AES key
//            SecretKeySpec skSpec = new SecretKeySpec(inputBuffer, "AES");
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//            SecretKey aeskey = keyFactory.generateSecret(skSpec);
            SecretKey aeskey = keyGen.generateKey();
            //Generate Cipher
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aeskey);

            //Encrypt the file
            byte[] cipherText = aesCipher.doFinal(inputBuffer);

            //Save encrypted file
            FileOutputStream outputStream = new FileOutputStream(outputDir + baseFileName + ".enc");
            outputStream.write(cipherText);
            outputStream.close();

            //Encrypt the aes key
            PBEKeySpec pbeKeySpec;
            SecretKeyFactory keyFac;
            // Salt
            byte[] salt = {
                    (byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c,
                    (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
            };

            // Iteration count
            int count = 20;

            // Create PBE parameter set
            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);

            pbeKeySpec = new PBEKeySpec(keyPassword.toCharArray());
            keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

            // Create PBE Cipher
            Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");

            // Initialize PBE Cipher with key and parameters
            pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

            // Encrypt the AES key
            byte[] ciphertext = pbeCipher.doFinal(aeskey.getEncoded());

            //Store encrypted AES key
            FileOutputStream keyOutputStream = new FileOutputStream(outputDir + baseFileName + ".key");
            keyOutputStream.write(cipherText);
            keyOutputStream.close();

            //Generate signature
/*            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(aeskey);
            sign.update(cipherText);
            byte[] signature = sign.sign();*/
        }
        catch(FileNotFoundException e){
            System.out.println("File: " + f2Encrypt.getName() + " does not exist");
            System.exit(1);
        }
        catch(Exception e){
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void decrypt(String filename){
        File f2Decrypt = new File(filename);
        checkIsRegistered(stripExtension(f2Decrypt.getName()), readWritePwds);
    }

    private void check(){

    }

    private static void functionUsagePrompt(){
        System.out.println("java Protect [option] [filename] [password]");
    }

    private void checkFilePassInput(String filename, String password){
        if(filename == null){
            System.out.println("No file name given");
            Test.functionUsagePrompt();
            System.exit(1);
        }
        else if(password == null){
            System.out.println("No password given");
            Test.functionUsagePrompt();
            System.exit(1);
        }
    }

    private void checkFileExists(File file){
        if(!file.exists()){
            System.out.println("File: " + file.getName() + " does not exist");
            System.exit(1);
        }
    }

    private void checkIsRegistered(String filename, HashMap<String, ReadWritePasswords> data){
        if(!data.containsKey(filename)){
            System.out.println("File is not registered");
            System.exit(1);
        }
    }

    private static String stripExtension(String filename){
        if(!filename.contains(".")){
            return filename;
        }
        else{
            return filename.substring(0, filename.indexOf("."));
        }
    }

    private static class WriteSecurityManager extends SecurityManager {
        String baseFilename;
        String password;
        HashMap<String, ReadWritePasswords> passwords;

        private WriteSecurityManager(String baseFilename, String password, HashMap<String, ReadWritePasswords> passwords){
            super();
            this.baseFilename = baseFilename;
            this.password = password;
            this.passwords = passwords;
        }

        private boolean writeOK(){
            return passwords.get(baseFilename).getWritePass().equals(password);
        }

        @Override
        public void checkWrite(FileDescriptor fileDescriptor) {
            if(!writeOK()){
                throw new SecurityException("No write access");
            }
        }

        @Override
        public void checkWrite(String s) {
            if(!writeOK()){
                throw new SecurityException("No write access");
            }
        }

        @Override
        public void checkRead(String s) {
        }

        @Override
        public void checkRead(String s, Object o) {
        }

        @Override
        public void checkRead(FileDescriptor fileDescriptor) {
        }
    }

    private static class ReadSecurityManager extends SecurityManager {
        String baseFilename;
        String password;
        HashMap<String, ReadWritePasswords> passwords;

        private ReadSecurityManager(String baseFilename, String password, HashMap<String, ReadWritePasswords> passwords){
            super();
            this.baseFilename = baseFilename;
            this.password = password;
            this.passwords = passwords;
        }

        private boolean readOK(){
            return passwords.get(baseFilename).getReadPass().equals(password);
        }

        @Override
        public void checkRead(String s) {
            if(!readOK()){
                throw new SecurityException("No read access");
            }
        }

        @Override
        public void checkRead(String s, Object o) {
            if(!readOK()){
                throw new SecurityException("No read access");
            }
        }

        @Override
        public void checkRead(FileDescriptor fileDescriptor) {
            if(!readOK()){
                throw new SecurityException("No read access");
            }
        }
    }

    private HashMap<String, ReadWritePasswords> getPasswordData(){
        HashMap<String, ReadWritePasswords> data = new HashMap<String, ReadWritePasswords>();
        try{
            File passwordList = new File("/home/chris/IdeaProjects/SysNetSecurity/Q1/Q1/passwords_list");
            System.out.println(passwordList.getAbsolutePath());
            if(!passwordList.exists()){
                System.exit(1);
            }
            Scanner reader = new Scanner(passwordList);

            //Trim lines and add to data - Exclude titles
            reader.nextLine();
            while(reader.hasNext()){
                String passwordLine = reader.nextLine().trim();
                String[] lineData = passwordLine.split("\t");
                data.put(lineData[0], new ReadWritePasswords(lineData[1],lineData[2]));
            }
        }
        catch(FileNotFoundException e){
            System.out.println("Password list not found");
        }
        return data;
    }

    private static class ReadWritePasswords {
        private String readPass;
        private String writePass;

        private ReadWritePasswords(String readPass, String writePass){
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
