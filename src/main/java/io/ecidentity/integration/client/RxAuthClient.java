package io.ecidentity.integration.client;

import com.google.protobuf.ByteString;
import io.ecidentity.integration.utils.Config;
import io.ecidentity.protocol.authority.*;
import io.ecidentity.protocol.types.KeyEntryTypeProtocol;
import io.ecidentity.protocol.types.ResultCodeExtProtocol;
import io.reactivex.Flowable;
import io.reactivex.Single;

import java.security.*;
import java.security.cert.CertificateException;

import static io.ecidentity.integration.utils.MessageUtils.getResultCode;

public class RxAuthClient extends ClientBase {

    public static class Builder {
        private final Config config;
        private String accessKeyId;
        private KeyStore keyStore;
        private char[] password;

        public Builder(Config config) {
            this.config = config;
        }

        public RxAuthClient.Builder withAccessKey(String accessKey) {
            this.accessKeyId = accessKey;
            return this;
        }

        public RxAuthClient.Builder withKeyStore(KeyStore keyStore) {
            this.keyStore = keyStore;
            return this;
        }

        public RxAuthClient.Builder withPassword(char[] password) {
            this.password = password;
            return this;
        }

        public RxAuthClient build() throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
            return new RxAuthClient(accessKeyId, keyStore, password, config);
        }
    }


    private final RxIntegrationAuthServiceGrpc.RxIntegrationAuthServiceStub integrationAuth;
    private final String accessKeyId;

    public RxAuthClient(String accessKeyId, KeyStore keyStore, char[] password, Config config) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException {
        super(config, keyStore, password);

        this.integrationAuth = RxIntegrationAuthServiceGrpc.newRxStub(authorityChannel);
        this.accessKeyId = accessKeyId;
    }

    public Single<InitAuthResponsePayload> init(String email, KeyEntryTypeProtocol type, byte[] hashToSign, Boolean report, Boolean subject, Boolean sanctions) {
        InitAuthRequestPayload payload = InitAuthRequestPayload.newBuilder()
                .setEmail(email)
                .setType(type)
                .setHashToSign(ByteString.copyFrom(hashToSign))
                .setWithReport(report)
                .setExtractSubject(subject)
                .setWithSanctions(sanctions)
                .build();
        byte[] signature;
        try {
            signature = signMessage(payload);
        } catch (Exception e) {
            return Single.error(new Exception(e.getMessage()));
        }
        return integrationAuth.init(InitAuthRequest.newBuilder()
                .setAccessKeyId(accessKeyId)
                .setSignature(ByteString.copyFrom(signature))
                .setPayload(payload)
                .build())
                .map(response -> (InitAuthResponsePayload) handleResponse(response));
    }

    public Flowable<AuthStatusResponsePayload> check(String sessionId) {
        AuthStatusRequestPayload payload = AuthStatusRequestPayload.newBuilder()
                .setSessionId(sessionId)
                .build();
        byte[] signature;
        try {
            signature = signMessage(payload);
        } catch (Exception e) {
            return Flowable.error(new Exception(e.getMessage()));
        }
        return integrationAuth.check(AuthStatusRequest.newBuilder()
                .setAccessKeyId(accessKeyId)
                .setSignature(ByteString.copyFrom(signature))
                .setPayload(payload)
                .build())
                .map(response -> (AuthStatusResponsePayload) handleResponse(response))
                .takeUntil(result -> getResultCode(result) != ResultCodeExtProtocol.PENDING);
    }

    public Flowable<AuthStatusResponsePayload> auth(
            String email, KeyEntryTypeProtocol type, byte[] hashToSign, Boolean report, Boolean subject, Boolean sanctions) {
        InitAuthRequestPayload payload = InitAuthRequestPayload.newBuilder()
                .setEmail(email)
                .setType(type)
                .setHashToSign(ByteString.copyFrom(hashToSign))
                .setWithReport(report)
                .setExtractSubject(subject)
                .setWithSanctions(sanctions)
                .build();
        byte[] signature;
        try {
            signature = signMessage(payload);
        } catch (Exception e) {
            return Flowable.error(new Exception(e.getMessage()));
        }
        return integrationAuth.auth(InitAuthRequest.newBuilder()
                .setAccessKeyId(accessKeyId)
                .setSignature(ByteString.copyFrom(signature))
                .setPayload(payload)
                .build())
                .map(response -> (AuthStatusResponsePayload) handleResponse(response))
                .takeUntil(result -> getResultCode(result) != ResultCodeExtProtocol.PENDING);
    }

    public Single<CancelAuthResponsePayload> cancel(String sessionId) {
        CancelAuthRequestPayload payload = CancelAuthRequestPayload.newBuilder()
                .setSessionId(sessionId)
                .build();
        byte[] signature;
        try {
            signature = signMessage(payload);
        } catch (Exception e) {
            return Single.error(new Exception(e.getMessage()));
        }
        return integrationAuth.cancel(CancelAuthRequest.newBuilder()
                .setAccessKeyId(accessKeyId)
                .setSignature(ByteString.copyFrom(signature))
                .setPayload(payload)
                .build())
                .map(response -> (CancelAuthResponsePayload) handleResponse(response));
    }
}