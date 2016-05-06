import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Protect {

    private HashMap<String, ReadWritePasswords> readWritePwds;
    private final String outputDir = "Q1/Q1/";

    public static void main(String[] args){
        Protect test = new Protect();
        String op = "";
        if(args.length == 0){
            Protect.functionUsagePrompt();
            System.exit(1);
        }
        else{
            op = args[0];
        }
        test.readWritePwds = test.getPasswordData();
        String baseFileName;

        if(op.equals("-e")){
            String filename = args[1];
            String password = args[2];
            test.checkFilePassInput(filename, password);
            File f2Encrypt = new File(filename);
            baseFileName = stripExtension(f2Encrypt.getName());
            //Set security policy
            System.setSecurityManager(new WriteSecurityManager(baseFileName, String.valueOf(password.hashCode()), test.readWritePwds));
            //Encrypt
            test.encrypt(f2Encrypt);
        }
        else if(op.equals("-d")){
            String filename = args[1];
            String password = args[2];
            test.checkFilePassInput(filename, password);
            File f2Decrypt = new File(filename);
            baseFileName = stripExtension(f2Decrypt.getName());
            //Set security policy
            System.setSecurityManager(new ReadSecurityManager(baseFileName, String.valueOf(password.hashCode()), test.readWritePwds));
            //Decrypt
            test.decrypt(f2Decrypt);
        }
        else if(op.equals("-c")){
            //Check
            test.check();
        }
        else{
            System.out.println("Operation must be one of the following:");
            System.out.println("-e = encrypt");
            System.out.println("-d = decrypt");
            System.out.println("-c = check");
            System.exit(1);
        }
    }

    private void encrypt(File f2Encrypt){
        String baseFileName = stripExtension(f2Encrypt.getName());
        checkIsRegistered(baseFileName, readWritePwds);

        try{
            //Get file bytes
            InputStream inputStream = new FileInputStream(f2Encrypt);
            byte[] inputBuffer = new byte[(int) f2Encrypt.length()];
            inputStream.read(inputBuffer);
            inputStream.close();

            //Encrypt the data using AES
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecretKey aeskey = keyGen.generateKey();
            byte[][] encryptedData = encryptAES(inputBuffer, aeskey);

            //Encrypt the AES key using RSA
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
            KeyPair kp = kpGen.genKeyPair();
            byte[] encryptedAESKey = encryptRSA(aeskey.getEncoded(), kp.getPublic());

            //Encrypt the RSA private key using PBE
            String readPassword = readWritePwds.get(baseFileName).getReadPass();
            byte[] encryptedPrivateKey = encryptPBE(kp.getPrivate().getEncoded(), readPassword);

            //Create signature
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(kp.getPrivate());
            sign.update(encryptedData[0]);
            byte[] signature = sign.sign();

            //Save encrypted data
            FileOutputStream outputStream = new FileOutputStream(outputDir + baseFileName + ".enc");
            outputStream.write(encryptedData[0]);
            outputStream.close();

            //Save AES IV
            outputStream = new FileOutputStream(outputDir + baseFileName + "AESIV.txt");
            outputStream.write(encryptedData[1]);
            outputStream.close();

            //Save encrypted AES key
            outputStream = new FileOutputStream(outputDir + baseFileName + "AESKey.txt");
            outputStream.write(encryptedAESKey);
            outputStream.close();

            //Save RSA public key
            outputStream = new FileOutputStream(outputDir + baseFileName + "PK.txt");
            outputStream.write(kp.getPublic().getEncoded());
            outputStream.close();

            //Save encrypted RSA private key
            outputStream = new FileOutputStream(outputDir + baseFileName + "SK.txt");
            outputStream.write(encryptedPrivateKey);
            outputStream.close();

            //Save signature
            outputStream = new FileOutputStream(outputDir + baseFileName + "SIGN.txt");
            outputStream.write(signature);
            outputStream.close();

            //Remove files
            f2Encrypt.delete();
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

    private void decrypt(File f2Decrypt){
        String baseFileName = stripExtension(f2Decrypt.getName());
        checkIsRegistered(baseFileName, readWritePwds);

        try{
            KeyFactory kf = KeyFactory.getInstance("RSA");

            //Get file bytes
            byte[] encryptedFileBuffer = getFileBytes(f2Decrypt);

            //Get public key bytes
            File pk = new File(outputDir + baseFileName + "PK.txt");
            byte[] pkBuffer = getFileBytes(pk);
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(pkBuffer));

            //Get encrypted private key bytes
            File encryptedSK = new File(outputDir + baseFileName + "SK.txt");
            byte[] encryptedSKBuffer = getFileBytes(encryptedSK);

            //Get encrypted aes key bytes
            File encryptedAES = new File(outputDir + baseFileName + "AESKey.txt");
            byte[] encryptedAESBuffer = getFileBytes(encryptedAES);

            //Get aes iv
            File aesIV = new File(outputDir + baseFileName + "AESIV.txt");
            byte[] aesIVBuffer = getFileBytes(aesIV);

            //Get signature bytes
            File signature = new File(outputDir + baseFileName + "SIGN.txt");
            byte[] signatureBuffer = getFileBytes(signature);

            //Verify signature
            Signature tempSignature = Signature.getInstance("SHA256withRSA");
            tempSignature.initVerify(publicKey);
            tempSignature.update(encryptedFileBuffer);
            if(!tempSignature.verify(signatureBuffer)){
                System.out.println("Signature can't be verified");
                System.exit(1);
            }

            //Decrypt private key
            String readPassword = readWritePwds.get(baseFileName).getReadPass();
            byte[] decryptedPrivateKey = decryptPBE(encryptedSKBuffer, readPassword);
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decryptedPrivateKey));

            //Decrypt AES key
            byte[] decryptedAESKey = decryptRSA(encryptedAESBuffer, privateKey);
            SecretKey aesKey = new SecretKeySpec(decryptedAESKey,0,decryptedAESKey.length, "AES");

            //Decrypt file
            byte[] decryptedFile = decryptAES(encryptedFileBuffer, aesKey, aesIVBuffer);

            //Save decrypted file
            FileOutputStream outputStream = new FileOutputStream(outputDir + baseFileName);
            outputStream.write(decryptedFile);
            outputStream.close();

            //Remove files
            f2Decrypt.delete();
            signature.delete();
            encryptedAES.delete();
            aesIV.delete();
            encryptedSK.delete();
            pk.delete();
        }
        catch(Exception e){
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void check(){
        ArrayList<String> fileList =  getFileList();
        File[] files = getFilesInDir(outputDir);

        /*No unencrypted files
        * Any unencrypted files are deleted*/
        System.out.println("Checking for unencrypted files");
        checkNoUnencrypted(fileList, files);

        files = getFilesInDir(outputDir);

        /*All encrypted files are correctly signed
        * Any encrypted file that does not correspond to the signature is deleted*/
        System.out.println("Checking Signatures");
        checkSignature(files);

        files = getFilesInDir(outputDir);

        /*No missing files compared to the original folder
        * Error message listing the missing files is displayed*/
        System.out.println("Checking for missing files");
        checkForMissingFiles(fileList, files);

        /*No extra file compared to the original folder
        * Any extra file is deleted*/
        System.out.println("Checking for extra files");
        checkForExtraFiles(fileList, files);
    }

    private byte[] encryptRSA(byte[] data, PublicKey publicKey){
        byte[] encrypted = new byte[0];
        try{
            //Generate RSA Cipher using public key
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            //Encrypt data
            encrypted = rsaCipher.doFinal(data);
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return encrypted;
    }

    private byte[][] encryptAES(byte[] data, SecretKey aeskey){
        byte[][] encrypted = new byte[2][0];
        try{
            //Generate Cipher
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aeskey);

            //Encrypt the file
            encrypted[0] = aesCipher.doFinal(data);
            //Get IV
            encrypted[1] = aesCipher.getIV();
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return encrypted;
    }

    private byte[] encryptPBE(byte[] data, String password){
        byte[] encrypted = new byte[0];
        try{
            // Salt
            byte[] salt = {
                    (byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c,
                    (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
            };

            // Iteration count
            int count = 20;

            // Create PBE parameter set
            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);

            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

            // Create PBE Cipher
            Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");

            // Initialize PBE Cipher with key and parameters
            pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

            // Encrypt the private key
            encrypted = pbeCipher.doFinal(data);
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return encrypted;
    }

    private byte[] decryptRSA(byte[] data, PrivateKey privateKey){
        byte[] encrypted = new byte[0];
        try{
            //Generate RSA Cipher using public key
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            //Encrypt data
            encrypted = rsaCipher.doFinal(data);
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return encrypted;
    }

    private byte[] decryptAES(byte[] data, SecretKey aeskey, byte[] iv){
        byte[] encrypted = new byte[0];
        try{
            //Generate Cipher
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            aesCipher.init(Cipher.DECRYPT_MODE, aeskey, ivSpec);

            //Encrypt the file
            encrypted = aesCipher.doFinal(data);
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return encrypted;
    }

    private byte[] decryptPBE(byte[] data, String password){
        byte[] encrypted = new byte[0];
        try{
            // Salt
            byte[] salt = {
                    (byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c,
                    (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
            };

            // Iteration count
            int count = 20;

            // Create PBE parameter set
            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);

            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

            // Create PBE Cipher
            Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");

            // Initialize PBE Cipher with key and parameters
            pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);

            // Encrypt the private key
            encrypted = pbeCipher.doFinal(data);
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return encrypted;
    }

    private static void functionUsagePrompt(){
        System.out.println("java Protect [option] [filename] [password]");
    }

    private byte[] getFileBytes(File file){
        byte[] buffer = new byte[0];
        try{
            //Get bytes
            InputStream inputStream = new FileInputStream(file);
            buffer = new byte[(int) file.length()];
            inputStream.read(buffer);
            inputStream.close();
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return buffer;
    }

    private ArrayList<String> getFileList(){
        ArrayList<String> fileNameList = new ArrayList<String>();
        File fileList = new File(outputDir + "file_list");

        try{
            FileReader fr = new FileReader(fileList);
            BufferedReader bf = new BufferedReader(fr);

            //Store all file names in list
            String fileName;
            while((fileName = bf.readLine()) != null){
                fileNameList.add(fileName);
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return fileNameList;
    }

    private File[] getFilesInDir(String directory){
        final File folder = new File(directory);
        if(folder.isDirectory()){
            return folder.listFiles();
        }
        else {
            throw new IllegalArgumentException(directory + " is not a directory");
        }
    }

    private ArrayList<File> getEncryptedFiles(File[] files){
        ArrayList<File> encryptedFiles = new ArrayList<File>();
        for(File file : files){
            if(file.getName().endsWith(".enc")){
                encryptedFiles.add(file);
            }
        }
        return encryptedFiles;
    }

    private void checkSignature(File[] files){
        ArrayList<File> encryptedFiles = getEncryptedFiles(files);
        for(File encryptedFile : encryptedFiles){
            //Is there a signature
            if(hasSignature(encryptedFile.getName(), files)){
                //Is it valid?
                try{
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    //Get public key and signature
                    File pk = new File(outputDir + stripExtension(encryptedFile.getName()) + "PK.txt");
                    File signature = new File(outputDir + stripExtension(encryptedFile.getName()) + "SIGN.txt");
                    byte[] pkBuffer = getFileBytes(pk);
                    PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(pkBuffer));

                    //If the signature isn't valid, delete the encrypted file
                    if(!verifySignature(publicKey, getFileBytes(encryptedFile), getFileBytes(signature))){
                        encryptedFile.delete();
                    }
                }
                catch(Exception e){
                    e.printStackTrace();
                }
            }
            else{
                //No signature -> delete
                encryptedFile.delete();
            }
        }
    }

    private boolean hasSignature(String fileName, File[] files){
        String expectedSignature = stripExtension(fileName) + "SIGN.txt";

        //Search through files for corresponding signature
        for(File file : files){
            if(file.getName().equals(expectedSignature)){
                return true;
            }
        }
        return false;
    }

    private boolean verifySignature(PublicKey pk, byte[] fileBytes, byte[] signatureBytes){
        boolean verify = false;
        try{
            Signature tempSignature = Signature.getInstance("SHA256withRSA");
            tempSignature.initVerify(pk);
            tempSignature.update(fileBytes);
            if(tempSignature.verify(signatureBytes)){
                verify = true;
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return verify;
    }

    private void checkNoUnencrypted(ArrayList<String> fileList, File[] files){
        for(File file : files){
            //If the file is unencrypted, delete it (Excludes aux files)
            if(fileList.contains(file.getName())){
                file.delete();
            }
        }
    }

    private void checkForMissingFiles(ArrayList<String> fileList, File[] files){
        ArrayList<String> missingFiles = new ArrayList<String>();
        for(String fileName : fileList){
            String expected = fileName + ".enc";
            //Is there an encrypted version?
            File tempFile = new File(outputDir + expected);
            List<File> fileObjectList = Arrays.asList(files);
            if(!fileObjectList.contains(tempFile)){
                missingFiles.add(fileName);
            }
        }
        if(!missingFiles.isEmpty()){
            for(String missingFile : missingFiles){
                System.out.println(missingFile + " is missing");
            }
        }
    }

    private void checkForExtraFiles(ArrayList<String> fileList, File[] files){
        ArrayList<String> filesToRemove = new ArrayList<String>();
        //Get all non-original .enc files
        for(File file : files){
            if(file.getName().endsWith(".enc") && !fileList.contains(stripExtension(file.getName()))){
                filesToRemove.add(file.getPath());
            }
        }

        //Delete files queued for removal
        for(String filePath : filesToRemove){
            File tempFile = new File(filePath);
            System.out.println("Deleting " + tempFile.getName());
            tempFile.delete();
        }
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

        @Override
        public void checkDelete(String s) {
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

        @Override
        public void checkWrite(FileDescriptor fileDescriptor) {
        }

        @Override
        public void checkWrite(String s) {
        }

        @Override
        public void checkDelete(String s) {
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
