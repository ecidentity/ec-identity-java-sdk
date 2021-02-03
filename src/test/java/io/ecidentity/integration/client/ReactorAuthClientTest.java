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
import static org.junit.Assert.assertTrue;

public class ReactorAuthClientTest extends TestBase {

    private final ReactorAuthClient client;

    public ReactorAuthClientTest() throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        super(ReactorAuthClientTest.class.getSimpleName());

        client = new ReactorAuthClient.Builder(Config.TEST)
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
                .blockLast();

        assertTrue(verify(randomHash,
                decodeX509Certificate(responsePayload.getCertificate().toByteArray()).getPublicKey(),
                responsePayload.getSignedHash().toByteArray()));
    }

    @Test
    public void testFlow() throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        byte[] randomHash = hash(new byte[0]);

        AuthStatusResponsePayload responsePayload = client.init(
                "basiljev@gmail.com",
                KeyEntryTypeProtocol.EMAIL,
                randomHash,
                false,
                true,
                false)
                .doOnNext(payload -> logger.info(payload.toString()))
                .flatMapMany(payload -> client.check(payload.getSessionId()))
                .doOnNext(payload -> logger.info(payload.toString()))
                .doOnError(throwable -> logger.info(throwable.toString()))
                .doOnComplete(() -> logger.info("Complete"))
                .blockLast();

        assertTrue(verify(randomHash,
                decodeX509Certificate(responsePayload.getCertificate().toByteArray()).getPublicKey(),
                responsePayload.getSignedHash().toByteArray()));
    }
}