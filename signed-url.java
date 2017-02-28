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
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

import org.apache.commons.codec.binary.Base64;


public class CFSignedUrl {

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
    public static byte[] readInputStreamToBytes(InputStream is) throws IOException {
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
    public static String toBase64(byte[] data) {
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
    protected static String makeBytesUrlSafe(byte[] bytes) throws UnsupportedEncodingException {
        return toBase64(bytes)
                .replace('+', '-')
                .replace('=', '_')
                .replace('/', '~');
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
    public static byte[] signWithRsaSha1(byte[] derPrivateKeyBytes, byte[] dataToSign)
        throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
        InvalidKeySpecException, NoSuchProviderException
    {
        // Build an RSA private key from private key data
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(derPrivateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);

        // Sign data
        /*Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Signature signature = Signature.getInstance("SHA1withRSA", "BC");*/
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
    public static String signUrlCanned(String resourceUrlOrPath,
                                       String keyPairId, byte[] derPrivateKey, Date epochDateLessThan)
            throws Exception {
        try {
            String cannedPolicy =
                    "{\"Statement\":[{\"Resource\":\"" + resourceUrlOrPath
                            + "\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":"
                            + epochDateLessThan.getTime() / 1000 + "}}}]}";

            byte[] signatureBytes = signWithRsaSha1(derPrivateKey,
                    cannedPolicy.getBytes("UTF-8"));

            String urlSafeSignature = makeBytesUrlSafe(signatureBytes);

            return resourceUrlOrPath
                    + (resourceUrlOrPath.indexOf('?') >= 0 ? "&" : "?")
                    + "Expires=" + epochDateLessThan.getTime() / 1000
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
    
    /**
     * Generate a policy document that describes custom access permissions to apply
     * via a private distribution's signed URL.
     *
     * @param resourcePath         An optional HTTP/S or RTMP resource path that restricts which distribution and S3 objects
     *                             will be accessible in a signed URL. For standard distributions the resource URL will be
     *                             <tt>"http://" + distributionName + "/" + objectKey</tt> (may also include URL
     *                             parameters. For distributions with the HTTPS required protocol, the resource URL
     *                             must start with <tt>"https://"</tt>. RTMP resources do not take the form of a URL,
     *                             and instead the resource path is nothing but the stream's name.
     *                             <p>
     *                             The '*' and '?' characters can be used as a wildcards to allow multi-character or
     *                             single-character matches respectively:
     *                             <ul>
     *                             <li><tt>*</tt> : All distributions/objects will be accessible</li>
     *                             <li><tt>a1b2c3d4e5f6g7.cloudfront.net/*</tt> : All objects within the distribution
     *                             a1b2c3d4e5f6g7 will be accessible</li>
     *                             <li><tt>a1b2c3d4e5f6g7.cloudfront.net/path/to/object.txt</tt> : Only the S3 object
     *                             named <tt>path/to/object.txt</tt> in the distribution a1b2c3d4e5f6g7 will be
     *                             accessible.</li>
     *                             </ul>
     *                             If this parameter is null the policy will permit access to all distributions and S3
     *                             objects associated with the certificate keypair used to generate the signed URL.
     * @param epochDateLessThan    The time and date when the signed URL will expire. REQUIRED.
     * @param limitToIpAddressCIDR An optional range of client IP addresses that will be allowed to access the distribution,
     *                             specified as a CIDR range. If null, the CIDR will be <tt>0.0.0.0/0</tt> and any
     *                             client will be permitted.
     * @param epochDateGreaterThan An optional time and date when the signed URL will become active. If null, the signed
     *                             URL will be active as soon as it is created.
     * @return A policy document describing the access permission to apply when generating a signed URL.
     * @throws CloudFrontServiceException exception
     */
    public static String buildPolicyForSignedUrl(
            String resourcePath, Date epochDateLessThan,
            String limitToIpAddressCIDR, Date epochDateGreaterThan)
            throws Exception {
        if(epochDateLessThan == null) {
            throw new Exception(
                    "epochDateLessThan must be provided to sign CloudFront URLs");
        }
        if(resourcePath == null) {
            resourcePath = "*";
        }
        String ipAddress = (limitToIpAddressCIDR == null
                ? "0.0.0.0/0"  // No IP restriction
                : limitToIpAddressCIDR);
        return "{\"Statement\": [{" +
                "\"Resource\":\"" + resourcePath + "\"" +
                ",\"Condition\":{" +
                "\"DateLessThan\":{\"AWS:EpochTime\":"
                + epochDateLessThan.getTime() / 1000 + "}" +
                ",\"IpAddress\":{\"AWS:SourceIp\":\"" + ipAddress + "\"}" +
                (epochDateGreaterThan == null ? ""
                        : ",\"DateGreaterThan\":{\"AWS:EpochTime\":"
                        + epochDateGreaterThan.getTime() / 1000 + "}") +
                "}}]}";
    }
    
    /**
     * Convert the given string to be safe for use in signed URLs for a private distribution.
     *
     * @param str
     * @return a URL-safe Base64 encoded version of the data.
     * @throws UnsupportedEncodingException
     */
    protected static String makeStringUrlSafe(String str) throws UnsupportedEncodingException {
        return toBase64(str.getBytes("UTF-8"))
                .replace('+', '-')
                .replace('=', '_')
                .replace('/', '~');
    }

    /**
     * Generate a signed URL that allows access to distribution and S3 objects by
     * applying access restrictions specified in a custom policy document.
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
     *                          use the utility method {@link EncryptionUtil#convertRsaPemToDer(java.io.InputStream)}
     * @param policy            A policy document that describes the access permissions that will be applied by the
     *                          signed URL. To generate a custom policy use
     *                          {@link #buildPolicyForSignedUrl(String, Date, String, Date)}.
     * @return A signed URL that will permit access to distribution and S3 objects as specified
     *         in the policy document.
     * @throws CloudFrontServiceException exception
     */
    public static String signUrl(String resourceUrlOrPath,
                                 String keyPairId, byte[] derPrivateKey, String policy)
            throws Exception {
        try {
            byte[] signatureBytes = signWithRsaSha1(derPrivateKey,
                    policy.getBytes("UTF-8"));

            String urlSafePolicy = makeStringUrlSafe(policy);
            String urlSafeSignature = makeBytesUrlSafe(signatureBytes);

            return resourceUrlOrPath
                    + (resourceUrlOrPath.indexOf('?') >= 0 ? "&" : "?")
                    + "Policy=" + urlSafePolicy
                    + "&Signature=" + urlSafeSignature
                    + "&Key-Pair-Id=" + keyPairId;
        }
        catch(RuntimeException e) {
            throw e;
        }
        catch(Exception e) {
            throw new Exception(e);
        }
    }

	public static void main(String[] args) throws Exception {
	
/*		AWSCredentials awsCredentials = new AWSCredentials(
		        "AKIAI3VAMX24BBXRTDHA", "ksIUBBmG9COjn2MiTPViO4sRnhauicPVuwEOeNoU");
		CloudFrontService cloudFrontService = new CloudFrontService(awsCredentials);
	
		String distributionId = "EREU5ZDWIEXUK";
		
		Distribution distribution = cloudFrontService.getDistributionInfo(distributionId);
		System.out.println("Active trusted signers: " + distribution.toString());
		System.out.println("Active trusted signers: " + distribution.getActiveTrustedSigners());*/
	
		// Obtain one of your own (Self) keypair ids that can sign URLs for the distribution
		
		/*List selfKeypairIds = (List) distribution.getActiveTrustedSigners().get("Self");
		String keyPairId = (String) selfKeypairIds.get(0);
		System.out.println("Keypair ID: " + keyPairId); */
	
		
		// Signed URLs for a private distribution
		// Note that Java only supports SSL certificates in DER format, 
		// so you will need to convert your PEM-formatted file to DER format. 
		// To do this, you can use openssl:
		// openssl pkcs8 -topk8 -nocrypt -in origin.pem -inform PEM -out new.der -outform DER 
		// So the encoder works correctly, you should also add the bouncy castle jar
		// to your project and then add the provider.
	
		//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	
		String distributionDomain = "d1lw5iruksdx6g.cloudfront.net";
		//String privateKeyFilePath = "D:\\Hoon\\workspace\\test\\src\\pk-APKAICXPW2IVRXISJ2YQ.der";
		String privateKeyFilePath = "D:\\Hoon\\workspace\\test\\src\\pk-APKAJY54CBXY7H526TLA.der";
		String objectKey = "test/index2.html";
		String policyResourcePath = "http://" + distributionDomain + "/" + objectKey;
	
		// Convert your DER file into a byte array.
	
		byte[] derPrivateKey = readInputStreamToBytes(new FileInputStream(privateKeyFilePath));
	
		// Generate a "canned" signed URL to allow access to a 
		// specific distribution and object

		long start = 0L;
		long end = 0L;
		long temp = 0L;
		
		start = System.currentTimeMillis();
		temp = start;
		//for(int i=0; i<100*1000; i++){
		String signedUrlCanned = CFSignedUrl.signUrlCanned(
		    "http://" + distributionDomain + "/" + objectKey, // Resource URL or Path
		    //"APKAICXPW2IVRXISJ2YQ",     // Certificate identifier,
		    "APKAJY54CBXY7H526TLA",     // Certificate identifier, 
		                   // an active trusted signer for the distribution
		    derPrivateKey, // DER Private key data
		    new Date(System.currentTimeMillis()+3000000)//ServiceUtils.parseIso8601Date("2014-08-22T10:40:00.000Z") // DateLessThan
		    );
		/*if(i%10000==0){
			end = System.currentTimeMillis();
			System.out.println("=====\t"+i + "\tXXXXX "+(end - temp));
			temp = end;
		}*/
		System.out.println(signedUrlCanned);
		//}
		end = System.currentTimeMillis();
		System.out.println("total"+(end -start));
	
		// Build a policy document to define custom restrictions for a signed URL.
	
/*		String policy = CloudFrontService.buildPolicyForSignedUrl(
		    // Resource path (optional, may include '*' and '?' wildcards)
		    policyResourcePath, 
		    // DateLessThan
		    ServiceUtils.parseIso8601Date("2014-09-31T22:20:00.000Z"), 
		    // CIDR IP address restriction (optional, 0.0.0.0/0 means everyone)
		    "0.0.0.0/0", 
		    // DateGreaterThan (optional)
		    ServiceUtils.parseIso8601Date("2014-01-01T06:31:56.000Z")
		    );
	
		// Generate a signed URL using a custom policy document.
	
		String signedUrl = CloudFrontService.signUrl(
		    // Resource URL or Path
		    "http://" + distributionDomain + "/" + objectKey, 
		    // Certificate identifier, an active trusted signer for the distribution
		    "IS2P2OZJZTW6VZJYLSR5R75ZVJIGFTUQ",     
		    // DER Private key data
		    derPrivateKey, 
		    // Access control policy
		    policy 
		    );
		System.out.println(signedUrl);
		
		
*/	
		// Build a policy document to define custom restrictions for a signed URL
        String policy = buildPolicyForSignedUrl(
        	"http://d3lsfm7awh826s.cloudfront.net/kmnet/_definst_/kmnet_480p.stream/*", // Resource path (optional, may include '*' and '?' wildcards)
            //ServiceUtils.parseIso8601Date("2009-11-14T22:20:00.000Z"), // DateLessThan
            new Date(System.currentTimeMillis()+30000000),//ServiceUtils.parseIso8601Date("2014-08-22T10:40:00.000Z") // DateLessThan
            "0.0.0.0/0", // CIDR IP address restriction (optional, 0.0.0.0/0 means everyone)
            //ServiceUtils.parseIso8601Date("2009-10-16T06:31:56.000Z")  // DateGreaterThan (optional)
            new Date(System.currentTimeMillis())//ServiceUtils.parseIso8601Date("2014-08-22T10:40:00.000Z") // DateLessThan
            );

        // Generate a signed URL using a custom policy document
        String signedUrl = CFSignedUrl.signUrl(
        	"http://d3lsfm7awh826s.cloudfront.net/kmnet/_definst_/kmnet_480p.stream/playlist.m3u8", // Domain name
            "APKAICXPW2IVRXISJ2YQ",     // Certificate identifier, an active trusted signer for the distribution
            derPrivateKey, // DER Private key data
            policy // Access control policy
            );
        System.out.println(signedUrl);

		}
}
