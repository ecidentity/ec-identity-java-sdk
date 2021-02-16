package io.ecidentity.integration.client;

import io.ecidentity.integration.utils.Config;
import io.ecidentity.protocol.authority.AuthStatusResponsePayload;
import io.ecidentity.protocol.types.KeyEntryTypeProtocol;
import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import static io.ecidentity.integration.client.Constants.ACCESS_KEY_ID;
import static io.ecidentity.integration.client.Constants.KEYSTORE_PASSWORD;
import static io.ecidentity.integration.utils.CryptoUtils.decodeX509Certificate;
import static io.ecidentity.integration.utils.CryptoUtils.verify;
import static org.junit.Assert.*;

public class RxAuthClientTest extends TestBase {

    private final RxAuthClient client;

    public RxAuthClientTest() throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        super(RxAuthClientTest.class.getSimpleName());

        client = new RxAuthClient.Builder(Config.TEST)
                .withAccessKey(ACCESS_KEY_ID)
                .withKeyStore(keyStore)
                .withPassword(KEYSTORE_PASSWORD.toCharArray())
                .build();
    }

    @Test
    public void testAuth() throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        byte[] randomHash = hash(new byte[0]);

        AuthStatusResponsePayload responsePayload = client.auth(
                "mail@mail.com",
                KeyEntryTypeProtocol.EMAIL,
                randomHash,
                false,
                true,
                false)
                .doOnNext(payload -> logger.info(payload.toString()))
                .doOnError(throwable -> logger.info(throwable.toString()))
                .doOnComplete(() -> logger.info("Complete"))
                .blockingLast();

        assertTrue(verify(randomHash,
                decodeX509Certificate(responsePayload.getCertificate().toByteArray()).getPublicKey(),
                responsePayload.getSignedHash().toByteArray()));
    }

    @Test
    public void testFlow() throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        byte[] randomHash = hash(new byte[0]);

        AuthStatusResponsePayload responsePayload = client.init(
                "mail@mail.com",
                KeyEntryTypeProtocol.EMAIL,
                randomHash,
                false,
                true,
                false)
                .flatMapPublisher(payload -> client.check(payload.getSessionId()))
                .doOnNext(payload -> logger.info(payload.toString()))
                .doOnError(throwable -> logger.info(throwable.toString()))
                .doOnComplete(() -> logger.info("Complete"))
                .blockingLast();

        assertTrue(verify(randomHash,
                decodeX509Certificate(responsePayload.getCertificate().toByteArray()).getPublicKey(),
                responsePayload.getSignedHash().toByteArray()));
    }
}