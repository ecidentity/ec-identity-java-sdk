package io.ecidentity.integration.client;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.Security;
import java.util.logging.Logger;

import static io.ecidentity.integration.client.Constants.KEYSTORE_PASSWORD;
import static io.ecidentity.integration.utils.CryptoUtils.sha256;

public class TestBase {

    protected Logger logger;
    protected KeyStore keyStore;

    TestBase(String loggerName) {
        Security.addProvider(new BouncyCastleProvider());
        logger = Logger.getLogger(loggerName);
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(getClass().getClassLoader().getResourceAsStream("client.p12"), KEYSTORE_PASSWORD.toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        } finally {
            logger.info("Tests started...");
        }
    }

    protected byte[] concat(byte[] a, byte[] b) {
        return ByteBuffer.allocate(a.length + b.length).put(a).put(b).array();
    }

    protected byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    protected byte[] hash(byte[] data) {
        return sha256(concat(data, longToBytes(System.currentTimeMillis())));
    }
}
