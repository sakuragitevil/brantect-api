package common;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.JWTClaimsVerifier;
import org.apache.commons.io.FileUtils;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

/**
 * Created by Thuan.Evi on 1/4/2017.
 */
public class TokenUtil {

    private static TokenUtil instance;
    private static HttpServletRequest httpRequest;
    private static int MD5_ITERATIONS = 1000;
    private static byte[] salt = {//8-byte
            (byte) 0xB2, (byte) 0x12, (byte) 0xD5, (byte) 0xB2,
            (byte) 0x44, (byte) 0x21, (byte) 0xC3, (byte) 0xC3
    };
    private static String secretKey = "";
    private static String resourcePath = "";

    private TokenUtil(HttpServletRequest httpReq) {
        httpRequest = httpReq;
        HttpSession session = httpRequest.getSession(false);
        this.resourcePath = session.getAttribute("realPath").toString() + "WEB-INF/classes/resources/";
    }

    public static TokenUtil getInstance(HttpServletRequest httpRequest) {
        TokenUtil.instance = new TokenUtil(httpRequest);
        return TokenUtil.instance;
    }

    /**
     * Generate json web token string
     *
     * @return ResponseUtil {Status, Response, Boolean, Technical, Exception}
     */
    public ResponseUtil rsaGenerator() {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            HttpSession session = httpRequest.getSession(false);
            secretKey = session.getAttribute("credentials").toString();
            final String[] arrCredentials = secretKey.split(":", 2);


            // initialize key generator
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            random.setSeed(secretKey.getBytes());

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048, random);

            // generate a keypair
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            // get key pair
            byte[] encodedPrivateKey = privateKey.getEncoded();
            byte[] encodedPublicKey = publicKey.getEncoded();
            responseUtil = base64EncodeToString(encodedPrivateKey);
            if (responseUtil.getStatus() == false)
                return responseUtil;
            String encodedPrivateKeyStr = responseUtil.getStringData();

            responseUtil = base64EncodeToString(encodedPublicKey);
            if (responseUtil.getStatus() == false)
                return responseUtil;
            String encodedPublicKeyStr = responseUtil.getStringData();

            responseUtil = secretKeyEncrypt(encodedPrivateKeyStr);
            if (responseUtil.getStatus() == false)
                return responseUtil;
            String encryptedPrivateKeyStr = responseUtil.getStringData();

            responseUtil = secretKeyEncrypt(encodedPublicKeyStr);
            if (responseUtil.getStatus() == false)
                return responseUtil;
            String encryptedPublicKeyStr = responseUtil.getStringData();

            // Write both keys to the file system
            FileUtils.writeStringToFile(new File(this.resourcePath + "rsa-private-" + arrCredentials[0] + ".pem"), encryptedPrivateKeyStr, "UTF-8");
            FileUtils.writeStringToFile(new File(this.resourcePath + "rsa-public-" + arrCredentials[0] + ".pem"), encryptedPublicKeyStr, "UTF-8");
            responseUtil.setBooleanData(true);

        } catch (IOException | NoSuchProviderException | NoSuchAlgorithmException e) {
            responseUtil.setStatus(false);
            responseUtil.setObjectData(null);
            responseUtil.setExceptionCause(e.getCause());
            responseUtil.setExceptionMessage(e.getMessage());
        }
        return responseUtil;
    }

    /**
     * Generate json web token string
     *
     * @return ResponseUtil {Status, Response, String, Technical, Exception}
     */
    public ResponseUtil jwtGenerator() {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            HttpSession session = httpRequest.getSession(false);
            secretKey = session.getAttribute("credentials").toString();
            final String[] arrCredentials = secretKey.split(":", 2);

            // Create RSAPrivateKey from pem file
            responseUtil = getRsaPrivateKey();
            if (responseUtil.getStatus() == false)
                return responseUtil;
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) responseUtil.getObjectData();

            // Create RSA-signer with the private key
            JWSSigner signer = new RSASSASigner(rsaPrivateKey);

            final Date NOW = new Date();
            Date exp = new Date(NOW.getTime() + 24 * 60 * 60 * 1000);
            Date nbf = new Date(NOW.getTime() - 24 * 60 * 60 * 1000);
            Date iat = new Date(NOW.getTime() / 1000 * 1000);

            // Prepare JWT with claims set
            JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder().
                    issuer("http://issuer.com").
                    subject(arrCredentials[0]).
                    audience(Collections.singletonList("http://audience.com")).
                    expirationTime(exp).
                    notBeforeTime(nbf).
                    issueTime(iat).
                    jwtID(UUID.randomUUID().toString()).
                    build();

            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaims);
            signedJWT.sign(signer);// Compute the RSA signature

            responseUtil = rsaEncrypt(signedJWT.getJWTClaimsSet());
            if (responseUtil.getStatus() == false)
                return responseUtil;

            String jwtEncrypt = responseUtil.getStringData();
            responseUtil.setStringData(jwtEncrypt);

        } catch (Exception e) {
            responseUtil.setStatus(false);
            responseUtil.setObjectData(null);
            responseUtil.setExceptionCause(e.getCause());
            responseUtil.setExceptionMessage(e.getMessage());
        }
        return responseUtil;
    }

    /**
     * Generate json web token string
     *
     * @return ResponseUtil {Status, Boolean, Technical, Exception}
     */
    public ResponseUtil jwtVerifier(String strJWT) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {
            responseUtil = rsaDecrypt(strJWT);
            if (responseUtil.getStatus() == false)
                return responseUtil;
            JWTClaimsSet jwtClaims = (JWTClaimsSet) responseUtil.getObjectData();
            JWTClaimsVerifier jwtClaimsVerifier = new DefaultJWTClaimsVerifier();
            jwtClaimsVerifier.verify(jwtClaims);
            responseUtil.setBooleanData(true);

        } catch (BadJOSEException e) {
            responseUtil.setStatus(false);
            responseUtil.setObjectData(null);
            responseUtil.setExceptionCause(e.getCause());
            responseUtil.setExceptionMessage(e.getMessage());
        }

        return responseUtil;
    }

    /**
     * Generate json web token string
     *
     * @return ResponseUtil {Status, RSAPrivateKey, Exception}
     */
    private static ResponseUtil getRsaPrivateKey() {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            HttpSession session = httpRequest.getSession(false);
            secretKey = session.getAttribute("credentials").toString();
            final String[] arrCredentials = secretKey.split(":", 2);
            String rsaPrivateKeyFilePath = resourcePath + "rsa-private-" + arrCredentials[0] + ".pem";

            File rsaPrivateKeyFile = new File(rsaPrivateKeyFilePath);
            if (!rsaPrivateKeyFile.exists()) {
                responseUtil.setStatus(false);
                responseUtil.setObjectData(null);
                responseUtil.setErrMessage("PrivateKey File not found");
                return responseUtil;
            }

            String strEncryptedRSAPrivateKey = FileUtils.readFileToString(rsaPrivateKeyFile, "UTF-8");
            responseUtil = secretKeyDecrypt(strEncryptedRSAPrivateKey);
            if (responseUtil.getStatus() == false)
                return responseUtil;
            String strDecryptedRSAPrivateKey = responseUtil.getStringData();

            responseUtil = base64DecodeToByte(strDecryptedRSAPrivateKey);
            if (responseUtil.getStatus() == false)
                return responseUtil;
            byte[] byteRSAPrivateKey = responseUtil.getBytesData();

            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(byteRSAPrivateKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            responseUtil.setObjectData(rsaPrivateKey);

        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            responseUtil.setStatus(false);
            responseUtil.setObjectData(null);
            responseUtil.setExceptionCause(e.getCause());
            responseUtil.setExceptionMessage(e.getMessage());
        }
        return responseUtil;
    }

    private static ResponseUtil getRsaPublicKey() {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {
            HttpSession session = httpRequest.getSession(false);
            secretKey = session.getAttribute("credentials").toString();
            final String[] arrCredentials = secretKey.split(":", 2);
            String rsaPublicKeyFilePath = resourcePath + "rsa-public-" + arrCredentials[0] + ".pem";
            File rsaPublicKeyFile = new File(rsaPublicKeyFilePath);
            if (!rsaPublicKeyFile.exists()) {
                responseUtil.setStatus(false);
                responseUtil.setObjectData(null);
                responseUtil.setErrMessage("PublicKey File not found");
                return responseUtil;
            }

            String strEncryptedRSAPublicKey = FileUtils.readFileToString(rsaPublicKeyFile, "UTF-8");
            responseUtil = secretKeyDecrypt(strEncryptedRSAPublicKey);
            if (responseUtil.getStatus() == false)
                return responseUtil;
            String strDecryptedRSAPublicKey = responseUtil.getStringData();

            responseUtil = base64DecodeToByte(strDecryptedRSAPublicKey);
            if (responseUtil.getStatus() == false)
                return responseUtil;
            byte[] byteRSAPublicKey = responseUtil.getBytesData();

            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(byteRSAPublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
            responseUtil.setObjectData(rsaPublicKey);

        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            responseUtil.setStatus(false);
            responseUtil.setObjectData(null);
            responseUtil.setExceptionCause(e.getCause());
            responseUtil.setExceptionMessage(e.getMessage());
        }
        return responseUtil;
    }

    private static ResponseUtil secretKeyEncrypt(String plaintext) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            PBEKeySpec pbeKeySpec = new PBEKeySpec(secretKey.toCharArray());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey key = keyFactory.generateSecret(pbeKeySpec);
            PBEParameterSpec paramSpec = new PBEParameterSpec(salt, MD5_ITERATIONS);
            Cipher cipher = Cipher.getInstance(key.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
            responseUtil = base64EncodeToString(cipher.doFinal(plaintext.getBytes(Charset.forName("UTF-8"))));
            if (responseUtil.getStatus() == false)
                return responseUtil;
            String strEncrypt = responseUtil.getStringData();
            responseUtil.setStringData(strEncrypt);

        } catch (IllegalBlockSizeException | InvalidKeySpecException | BadPaddingException | NoSuchPaddingException |
                InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            responseUtil.setStatus(false);
            responseUtil.setObjectData(null);
            responseUtil.setExceptionCause(e.getCause());
            responseUtil.setExceptionMessage(e.getMessage());
        }
        return responseUtil;
    }

    private static ResponseUtil secretKeyDecrypt(String plaintext) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            PBEKeySpec pbeKeySpec = new PBEKeySpec(secretKey.toCharArray());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey key = keyFactory.generateSecret(pbeKeySpec);
            PBEParameterSpec paramSpec = new PBEParameterSpec(salt, MD5_ITERATIONS);
            Cipher cipher = Cipher.getInstance(key.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

            responseUtil = base64DecodeToByte(plaintext);
            if (responseUtil.getStatus() == false)
                return responseUtil;
            byte[] decodeByte = responseUtil.getBytesData();
            String decryptStr = new String(cipher.doFinal(decodeByte), Charset.forName("UTF-8"));
            responseUtil.setStringData(decryptStr);

        } catch (IllegalBlockSizeException | InvalidKeySpecException | BadPaddingException | NoSuchAlgorithmException |
                InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
            responseUtil.setStatus(false);
            responseUtil.setObjectData(null);
            responseUtil.setExceptionCause(e.getCause());
            responseUtil.setExceptionMessage(e.getMessage());
        }
        return responseUtil;
    }

    private static ResponseUtil rsaEncrypt(JWTClaimsSet jwtClaims) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            // Create RSAPublicKey from pem file
            responseUtil = getRsaPublicKey();
            if (responseUtil.getStatus() == false)
                return responseUtil;
            RSAPublicKey rsaPublicKey = (RSAPublicKey) responseUtil.getObjectData();


            // Request JWT encrypted with RSA-OAEP and 128-bit AES/GCM
            JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);

            // Create the encrypted JWT object
            EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaims);

            // Create an encrypter with the specified public RSA key
            RSAEncrypter encrypter = new RSAEncrypter(rsaPublicKey);
            encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

            // Do the actual encryption
            encryptedJWT.encrypt(encrypter);
            String jwtEncrypted = encryptedJWT.serialize();
            responseUtil.setStringData(jwtEncrypted);

        } catch (JOSEException e) {
            responseUtil.setStatus(false);
            responseUtil.setObjectData(null);
            responseUtil.setExceptionCause(e.getCause());
            responseUtil.setExceptionMessage(e.getMessage());
        }
        return responseUtil;
    }

    private static ResponseUtil rsaDecrypt(String jwtString) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            // Create RSAPrivateKey from pem file
            responseUtil = getRsaPrivateKey();
            if (responseUtil.getStatus() == false)
                return responseUtil;
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) responseUtil.getObjectData();

            // Parse back
            EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwtString);

            // Create a decrypter with the specified private RSA key
            RSADecrypter decrypter = new RSADecrypter(rsaPrivateKey);
            decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

            // Decrypt
            encryptedJWT.decrypt(decrypter);
            JWTClaimsSet jwtClaims = encryptedJWT.getJWTClaimsSet();
            responseUtil.setObjectData(jwtClaims);

        } catch (JOSEException | ParseException e) {
            responseUtil.setStatus(false);
            responseUtil.setObjectData(null);
            responseUtil.setExceptionCause(e.getCause());
            responseUtil.setExceptionMessage(e.getMessage());
        }
        return responseUtil;
    }

    private static ResponseUtil base64EncodeToString(byte[] bytes) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        String base64Encoder = Base64.getEncoder().encodeToString(bytes);
        responseUtil.setStringData(base64Encoder);
        return responseUtil;
    }

    public static ResponseUtil base64DecodeToByte(String plaintext) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        byte[] base64Decoder = Base64.getDecoder().decode(plaintext);
        responseUtil.setBytesData(base64Decoder);
        return responseUtil;
    }

    public static ResponseUtil base64DecodeToString(String plaintext) {
        ResponseUtil responseUtil = ResponseUtil.getInstance();
        String base64Decoder = new String(Base64.getDecoder().decode(plaintext), Charset.forName("UTF-8"));
        responseUtil.setStringData(base64Decoder);
        return responseUtil;
    }

    public static boolean rsaFileExists() {

        HttpSession session = httpRequest.getSession(false);
        secretKey = session.getAttribute("credentials").toString();
        final String[] arrCredentials = secretKey.split(":", 2);
        String rsaPrivateKeyFilePath = resourcePath + "rsa-private-" + arrCredentials[0] + ".pem";
        String rsaPublicKeyFilePath = resourcePath + "rsa-public-" + arrCredentials[0] + ".pem";

        File rsaPrivateKeyFile = new File(rsaPrivateKeyFilePath);
        File rsaPublicKeyFile = new File(rsaPublicKeyFilePath);
        if (!rsaPrivateKeyFile.exists() || !rsaPublicKeyFile.exists())
            return false;
        return true;
    }

}
