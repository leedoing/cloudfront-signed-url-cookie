package com.gscdn.broker.util;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;


public class CfSignedUrlCookie {
	
    /**
     * Reads binary data from an input stream and returns it as a byte array.
     *
     * @param is
     * input stream from which data is read.
     *
     * @return
     * byte array containing data read from the input stream.
     *
     * @throws IOException
     */
    public static byte[] readInputStreamToBytes(InputStream is) throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int b = -1;
        while ((b = is.read()) != -1) {
            baos.write(b);
        }
        return baos.toByteArray();
    }
    
    /**
     * Converts byte data to a Base64-encoded string.
     *
     * @param data
     * data to Base64 encode.
     * @return
     * encoded Base64 string.
     */
    public static String toBase64(byte[] data)
    {
        byte[] b64 = Base64.encodeBase64(data);
        try {
            return new String(b64, "UTF-8");
        }
        catch(UnsupportedEncodingException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
	
    /**
     * Convert the given data to be safe for use in signed URLs for a private distribution by
     * using specialized Base64 encoding.
     *
     * @param bytes
     * @return a URL-safe Base64 encoded version of the data.
     * @throws UnsupportedEncodingException
     */
    protected static String makeBytesUrlSafe(byte[] bytes) throws UnsupportedEncodingException
    {
        return toBase64(bytes).replace('+', '-').replace('=', '_').replace('/', '~');
    }
    
    /**
     * Generate an RSA SHA1 signature of the given data using the given private
     * key DER certificate.
     *
     * Based on example code from:
     * http://www.java2s.com/Tutorial/Java/0490__Security/RSASignatureGeneration.htm
     * http://forums.sun.com/thread.jspa?threadID=5175986
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws InvalidKeySpecException
     * @throws NoSuchProviderException
     */
    public static byte[] signWithRsaSha1(byte[] derPrivateKeyBytes, byte[] dataToSign) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException, NoSuchProviderException
    {
        // Build an RSA private key from private key data
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(derPrivateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);

        // Sign data
        Signature signature = Signature.getInstance("SHA1withRSA", "SunJSSE");
        signature.initSign(privateKey, new SecureRandom());
        signature.update(dataToSign);

        byte[] signatureBytes = signature.sign();
        return signatureBytes;
    }
    
    /**
     * Generate a signed URL that allows access to a specific distribution and
     * S3 object by applying a access restrictions from a "canned" (simplified)
     * policy document.
     *
     * @param resourceUrlOrPath The URL or path that uniquely identifies a resource within a distribution.
     *                          For standard distributions the resource URL will be
     *                          <tt>"http://" + distributionName + "/" + objectKey</tt> (may also include URL
     *                          parameters. For distributions with the HTTPS required protocol, the resource URL
     *                          must start with <tt>"https://"</tt>. RTMP resources do not take the form of a URL,
     *                          and instead the resource path is nothing but the stream's name.
     * @param keyPairId         Identifier of a public/private certificate keypair already configured in your
     *                          Amazon Web Services account.
     * @param derPrivateKey     The RSA private key data that corresponding to the certificate keypair identified by
     *                          keyPairId, in DER format. To convert a standard PEM private key file into this format
     *                          use the utility method
     * @param epochDateLessThan The time and date when the signed URL will expire. REQUIRED.
     * @return A signed URL that will permit access to a specific distribution and S3 object.
     * @throws eException exception
     */
    public static String signUrlCanned(String resourceUrlOrPath, String keyPairId, byte[] derPrivateKey, long epochDateLessThan) throws Exception
    {
        try {
            String cannedPolicy =
                    "{\"Statement\":[{\"Resource\":\"" + resourceUrlOrPath
                            + "\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":"
                            + epochDateLessThan + "}}}]}";

            byte[] signatureBytes = signWithRsaSha1(derPrivateKey, cannedPolicy.getBytes("UTF-8"));

            String urlSafeSignature = makeBytesUrlSafe(signatureBytes);

            return resourceUrlOrPath
                    + (resourceUrlOrPath.indexOf('?') >= 0 ? "&" : "?")
                    + "Expires=" + epochDateLessThan
                    + "&Signature=" + urlSafeSignature
                    + "&Key-Pair-Id=" + keyPairId;
        }
        catch(RuntimeException e) {
            throw e;
        }
        catch(Exception e) {
            throw e;
        }
    }
    
    public static String signUrlCannedCookie(String domain, String path, String keyPairId, byte[] derPrivateKey, long epochDateLessThan) throws Exception
    {
        try {
            String cannedPolicy =
                    "{\"Statement\":[{\"Resource\":\"" + "http://" + domain + path
                            + "\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":"
                            + epochDateLessThan + "}}}]}";

            byte[] signatureBytes = signWithRsaSha1(derPrivateKey, cannedPolicy.getBytes("UTF-8"));

            String urlSafeSignature = makeBytesUrlSafe(signatureBytes);

            return "Set-Cookie: Domain=" + domain + "; Path=" + path + "; Secure; HttpOnly; CloudFront-Expires=" + epochDateLessThan + "; CloudFront-Signature=" + urlSafeSignature + "; CloudFront-Key-Pair-Id=" + keyPairId;
         //   + ";";
        }
        catch(RuntimeException e) {
            throw e;
        }
        catch(Exception e) {
            throw e;
        }
    }

	public static void main(String[] args) throws Exception {
	
		String distributionDomain = "d1ju52jpb3vnhd.cloudfront.net";
		String privateKeyFilePath = "D:\\Hoon\\workspace\\test\\src\\pk-APKAJY54CBXY7H526TLA.der";
		//String objectKey = "catv/_definst_/catv_720p.stream/playlist.m3u8";
		String objectKey = "/index2.html";
		String policyResourcePath = "http://" + distributionDomain + "/" + objectKey;
	
		// Convert your DER file into a byte array.
	
		byte[] derPrivateKey = readInputStreamToBytes(new FileInputStream(privateKeyFilePath));
		
		String certificateIdentifier = "APKAJY54CBXY7H526TLA";
	
		// Generate a "canned" signed URL to allow access to a 
		// specific distribution and object

		//for(int i=0; i<1000*1000; i++){
		String signedUrlCanned = CfSignedUrlCookie.signUrlCanned(
			    "http://" + distributionDomain + objectKey, // Resource URL or Path
			    certificateIdentifier,     // Certificate identifier, 
			                   // an active trusted signer for the distribution
			    derPrivateKey, // DER Private key data
			    System.currentTimeMillis()/1000+3600//ServiceUtils.parseIso8601Date("2014-08-22T10:40:00.000Z") // DateLessThan
			    );
		/*if(i%10000==0){
			end = System.currentTimeMillis();
			System.out.println("=====\t"+i + "\tXXXXX "+(end - temp));
			temp = end;
		}*/
		System.out.println(signedUrlCanned);
		//}
		
		signedUrlCanned = CfSignedUrlCookie.signUrlCannedCookie(
				distributionDomain,
				objectKey,
			    certificateIdentifier,     // Certificate identifier, 
			                   // an active trusted signer for the distribution
			    derPrivateKey, // DER Private key data
			    System.currentTimeMillis()/1000+3600//ServiceUtils.parseIso8601Date("2014-08-22T10:40:00.000Z") // DateLessThan
			    );
		System.out.println(signedUrlCanned);
	}
}

