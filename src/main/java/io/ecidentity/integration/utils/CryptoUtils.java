package io.ecidentity.integration.utils;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.crypto.EphemeralKeyPair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import sun.net.www.http.HttpClient;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public class CryptoUtils {

    public static final String ID = "Id";
    public static final String EMAIL = "EmailAddress";
    public static final String FIRST_NAME = "GivenName";
    public static final String LAST_NAME = "Surname";
    public static final String BIRTH_DATE = "DateOfBirth";
    public static final String GENDER = "Gender";
    public static final String CITIZENSHIP = "CountryOfCitizenship";
    public static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";


    public static SecureRandom newSecureRandom() throws NoSuchAlgorithmException {
        return SecureRandom.getInstance("NativePRNGNonBlocking");
    }

    public static byte[] encodeSignature(BigInteger r, BigInteger s, Byte v) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DERSequenceGenerator seq = new DERSequenceGenerator(bos);
        seq.addObject(new ASN1Integer(r));
        seq.addObject(new ASN1Integer(s));
        seq.addObject(new ASN1Integer((long) v));
        seq.close();
        return bos.toByteArray();
    }
    
    public static PrivateKey getPrivateKeyFromPem(String pem) throws IOException {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PEMParser pemParser = new PEMParser(new StringReader(pem));
        Object keyObject = pemParser.readObject();
        pemParser.close();
        return converter.getKeyPair((PEMKeyPair) keyObject).getPrivate();
    }

    public static PublicKey getPublicKeyFromPem(String pem) throws IOException {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PEMParser pemParser = new PEMParser(new StringReader(pem));
        Object keyObject = pemParser.readObject();
        pemParser.close();
        return converter.getPublicKey((SubjectPublicKeyInfo) keyObject);
    }

    public static Map<String, String> getSubjectData(X509Certificate certificate) throws CertificateEncodingException {
        X500Name x500Name = new JcaX509CertificateHolder(certificate).getSubject();

        return Arrays.stream(x500Name.getAttributeTypes()).map(x -> {
            String key = EcStyle.INSTANCE.oidToDisplayName(x);
            ASN1Encodable encodable = x500Name.getRDNs(x)[0].getFirst().getValue();
            String value;

            if (encodable instanceof ASN1GeneralizedTime){
                value = new SimpleDateFormat(DATE_FORMAT).format(encodable);
            }else if(encodable instanceof DERPrintableString){
                value = ((DERPrintableString) encodable).getString();
            }else if(encodable instanceof DERIA5String){
                value = ((DERIA5String) encodable).getString();
            }else if(encodable instanceof DERUTF8String){
                value = ((DERUTF8String) encodable).getString();
            }else{
                value = encodable.toString();
            }
            return new AbstractMap.SimpleEntry<>(key, value);
        }).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    public static X509Certificate decodeX509Certificate(byte[] encoded) throws CertificateException, NoSuchProviderException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encoded));
    }

    public static String calculateVerificationCode(byte[] hash) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(hash);
        int shortBytes = Short.SIZE / Byte.SIZE;
        int rightMostBytesIndex = byteBuffer.limit() - shortBytes;
        short twoRightmostBytes = byteBuffer.getShort(rightMostBytesIndex);
        int positiveInteger = ((int) twoRightmostBytes) & 0xffff;
        String code = String.valueOf(positiveInteger);
        String paddedCode = "0000" + code;
        return paddedCode.substring(code.length());
    }


    public static byte[] sign(byte[] hash, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update(hash);
        return signer.sign();
    }

    public static Boolean verify(byte[] hash, PublicKey publicKey, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initVerify(publicKey);
        signer.update(hash);
        return signer.verify(signature);
    }

    public static byte[] sha256(byte[] data){
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
