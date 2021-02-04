package io.ecidentity.integration.client;

import io.ecidentity.integration.utils.Config;
import io.ecidentity.protocol.authority.SignHashResponsePayload;
import io.ecidentity.protocol.types.KeyEntryTypeProtocol;
import io.ecidentity.protocol.types.ResultCodeExtProtocol;
import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import static io.ecidentity.integration.client.Constants.ACCESS_KEY_ID;
import static io.ecidentity.integration.client.Constants.KEYSTORE_PASSWORD;
import static org.junit.Assert.assertTrue;

public class RxSignClientTest extends TestBase {

    private final RxSignClient client;

    public RxSignClientTest() throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        super(RxSignClientTest.class.getSimpleName());

        client = new RxSignClient.Builder(Config.TEST)
                .withAccessKey(ACCESS_KEY_ID)
                .withKeyStore(keyStore)
                .withPassword(KEYSTORE_PASSWORD.toCharArray())
                .build();
    }

    @Test
    public void test() {

        SignHashResponsePayload signHashResponsePayload = client.init(
                "mail@mail.com", // Email address registered on demo.ecidentity.io
                KeyEntryTypeProtocol.EMAIL)
                .doOnNext(payload -> logger.info(payload.toString()))
                .lastElement()
                .flatMapPublisher(payload -> client.hash(payload.getSessionId(), hash(payload.getCertificate().toByteArray())))
                .doOnNext(payload -> logger.info(payload.toString()))
                .doOnError(throwable -> logger.info(throwable.toString()))
                .doOnComplete(() -> logger.info("Complete"))
                .blockingLast();

        assertTrue(signHashResponsePayload.getResultCode().equals(ResultCodeExtProtocol.OK));
    }
}