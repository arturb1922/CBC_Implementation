import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class Main {

    static byte [] plain = "Loremipsumdolorsitamet,consurpo.".getBytes();
    static byte [] key = "klucz--128-bitow".getBytes();
    static byte [] IV = "wektorwektorwekt".getBytes();

    public static byte[] xorWithKey(byte[] a, byte[] key) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ key[i%key.length]);
        }
        return out;
    }

    public static byte [] encrypt (byte[] plainText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        byte [] temp= new byte[16];
        temp= Arrays.copyOf(plain,temp.length);

        byte [] result=xorWithKey(temp,IV);

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte firstEncrypted[] = cipher.doFinal(result);


        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(firstEncrypted);

        int length = plain.length/16;
        if(plain.length% 16!=0)
        {
            length+=1;
        }



        for (int i=1;i<length;i++)
        {
            byte [] chunk = Arrays.copyOfRange(plain,i*16,i*32);
            byte [] xor = xorWithKey(chunk,firstEncrypted);
            cipher.init(Cipher.ENCRYPT_MODE,secretKey);
            byte [] loopEncryption = cipher.doFinal(xor);
            baos.write(loopEncryption);

        }


        byte [] encryptedAll = baos.toByteArray();


        return encryptedAll;
    }


    public static byte [] decrypt (byte [] encryptedText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        byte [] temp;
        temp=Arrays.copyOf(encryptedText,16);

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte decrypted[] = cipher.doFinal(temp);


        byte [] xorDecrypted = xorWithKey(decrypted,IV);


        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(xorDecrypted);

        int length = encryptedText.length/16;
        if(encryptedText.length% 16!=0)
        {
            length+=1;
        }



        for (int i=1;i<length;i++)
        {
            byte [] chunk = Arrays.copyOfRange(encryptedText,i*16,i*32);
            cipher.init(Cipher.DECRYPT_MODE,secretKey);
            byte [] loopDecryption = cipher.doFinal(chunk);
            byte [] xor = xorWithKey(temp,loopDecryption);
            baos.write(xor);

        }


        byte [] decryptedAll = baos.toByteArray();


        return decryptedAll;


    }

    public static void main(String[] args) throws Exception {

        String plainString= new String(plain, StandardCharsets.UTF_8);

        String encryptedString;
        String decryptedStrng;

        // szyfrowanie
        long startTime1= System.nanoTime();
        byte [] resultOfEncrypt = encrypt(plain);
        long estimatedTime1 = System.nanoTime()-startTime1;

        System.out.println("The orginal text was " + plainString);

        encryptedString=new String (resultOfEncrypt,"UTF-8");
        System.out.println("Time estimated to encrypt with CBC mode: " + estimatedTime1+ " ns");
        System.out.println("The encrypted message " + encryptedString);

        // deszyfrowanie
        long startTime2= System.nanoTime();
        byte [] resultOfDecrypt = decrypt(resultOfEncrypt);
        long estimatedTime2 = System.nanoTime()-startTime1;
        decryptedStrng = new String( resultOfDecrypt,"UTF-8");
        System.out.println("Time estimated to decrypt with CBC mode: " + estimatedTime2 +" ns");
        System.out.println("The result of decryption " + decryptedStrng);
    }




}