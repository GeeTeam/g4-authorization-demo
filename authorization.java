import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Formatter;
import java.util.List;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


class SortByStr implements Comparator {
 
	public int compare(Object o1, Object o2) { 
		String s1 = (String) o1;
		String s2 = (String) o2;
		return s1.compareTo(s2);
	}
}

public class gen {

    private static final String HASH_ALGORITHM = "HmacSHA256";
    public static final String SOURCES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";

    static String timestamp = Long.toString(System.currentTimeMillis()/1000);
    static String nonce = generateString(new Random(), SOURCES, 32);

    public static String generateString(Random random, String characters, int length) {
        char[] text = new char[length];
        for (int i = 0; i < length; i++) {
            text[i] = characters.charAt(random.nextInt(characters.length()));
        }
        return new String(text);
    }
    
    public static String genOriString(String gt_id){

        ArrayList<String> joinlist = new ArrayList<String>();
        joinlist.add(gt_id);
        joinlist.add(timestamp);
        joinlist.add(nonce);
        Collections.sort(joinlist, new SortByStr());
        
        StringBuffer joinstr = new StringBuffer();
        for (int i = 0; i < joinlist.size(); i++) {  
            joinstr.append(joinlist.get(i));
        }  

        String OriString = joinstr.toString();
        return OriString;
    }

    public static String genEncryptString(String genOriString, String gt_key)throws SignatureException {
        try{
            Key sk = new SecretKeySpec(gt_key.getBytes(), HASH_ALGORITHM);
            Mac mac = Mac.getInstance(sk.getAlgorithm());
            mac.init(sk);
            final byte[] hmac = mac.doFinal(genOriString.getBytes());
            StringBuilder sb = new StringBuilder(hmac.length * 2);  

                @SuppressWarnings("resource")
                Formatter formatter = new Formatter(sb);  
                for (byte b : hmac) {  
                    formatter.format("%02x", b);  
                }  
            String EncryptedString = sb.toString();
            return EncryptedString;
        }catch (NoSuchAlgorithmException e1){
            throw new SignatureException("error building signature, no such algorithm in device "+ HASH_ALGORITHM);
        }catch (InvalidKeyException e){
            throw new SignatureException("error building signature, invalid key " + HASH_ALGORITHM);
        }
    }

    public static String genHeaderParam(String gt_id, String gt_key) throws SignatureException{
    
        String GenOriString = genOriString(gt_id);
        
        String EncryptedString = genEncryptString(GenOriString, gt_key);

        String HeaderParam = "gt_id=" + gt_id 
                     +",timestamp=" + timestamp 
                         +",nonce=" + nonce 
                     +",signature=" + EncryptedString;
        return HeaderParam;
    }

    public static void main(String[] args) throws SignatureException{
        String res = genHeaderParam("95W9R2Bwt5TfBVmEMMdg7gaKJXesme0Y", "J8ZxMJmevwpdYCe2IUCI62ffqa9weHnM");
        System.out.println(res);
    }
}
