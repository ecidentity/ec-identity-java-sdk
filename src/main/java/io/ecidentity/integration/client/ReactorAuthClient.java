package io.ecidentity.integration.client;

import com.google.protobuf.ByteString;
import io.ecidentity.integration.utils.Config;
import io.ecidentity.protocol.authority.*;
import io.ecidentity.protocol.types.KeyEntryTypeProtocol;
import io.ecidentity.protocol.types.ResultCodeExtProtocol;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.security.*;
import java.security.cert.CertificateException;

import static io.ecidentity.integration.utils.MessageUtils.getResultCode;

public class ReactorAuthClient extends ClientBase {

    public static class Builder {
        private final Config config;
        private String accessKeyId;
        private KeyStore keyStore;
        private char[] password;

        public Builder(Config config) {
            this.config = config;
        }

        public ReactorAuthClient.Builder withAccessKey(String accessKey) {
            this.accessKeyId = accessKey;
            return this;
        }

        public ReactorAuthClient.Builder withKeyStore(KeyStore keyStore) {
            this.keyStore = keyStore;
            return this;
        }

        public ReactorAuthClient.Builder withPassword(char[] password) {
            this.password = password;
            return this;
        }

        public ReactorAuthClient build() throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
            return new ReactorAuthClient(accessKeyId, keyStore, password, config);
        }
    }


    private final ReactorIntegrationAuthServiceGrpc.ReactorIntegrationAuthServiceStub integrationAuth;
    private final String accessKeyId;

    public ReactorAuthClient(String accessKeyId, KeyStore keyStore, char[] password, Config config) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException {
        super(config, keyStore, password);

        this.integrationAuth = ReactorIntegrationAuthServiceGrpc.newReactorStub(authorityChannel);
        this.accessKeyId = accessKeyId;
    }

    public Mono<InitAuthResponsePayload> init(String email, KeyEntryTypeProtocol type, byte[] hashToSign, Boolean report, Boolean subject, Boolean sanctions) {
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
            return Mono.error(new Exception(e.getMessage()));
        }
        return integrationAuth.init(InitAuthRequest.newBuilder()
                .setAccessKeyId(accessKeyId)
                .setSignature(ByteString.copyFrom(signature))
                .setPayload(payload)
                .build())
                .map(response -> (InitAuthResponsePayload) handleResponse(response));
    }

    public Flux<AuthStatusResponsePayload> check(String sessionId) {
        AuthStatusRequestPayload payload = AuthStatusRequestPayload.newBuilder()
                .setSessionId(sessionId)
                .build();
        byte[] signature;
        try {
            signature = signMessage(payload);
        } catch (Exception e) {
            return Flux.error(new Exception(e.getMessage()));
        }
        return integrationAuth.check(AuthStatusRequest.newBuilder()
                .setAccessKeyId(accessKeyId)
                .setSignature(ByteString.copyFrom(signature))
                .setPayload(payload)
                .build())
                .map(response -> (AuthStatusResponsePayload) handleResponse(response))
                .takeUntil(result -> getResultCode(result) != ResultCodeExtProtocol.PENDING);
    }

    public Flux<AuthStatusResponsePayload> auth(String email, KeyEntryTypeProtocol type, byte[] hashToSign, Boolean report, Boolean subject, Boolean sanctions) {
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
            return Flux.error(new Exception(e.getMessage()));
        }
        return integrationAuth.auth(InitAuthRequest.newBuilder()
                .setAccessKeyId(accessKeyId)
                .setSignature(ByteString.copyFrom(signature))
                .setPayload(payload)
                .build())
                .map(response -> (AuthStatusResponsePayload) handleResponse(response))
                .takeUntil(result -> getResultCode(result) != ResultCodeExtProtocol.PENDING);
    }

    public Mono<CancelAuthResponsePayload> cancel(String sessionId) {
        CancelAuthRequestPayload payload = CancelAuthRequestPayload.newBuilder()
                .setSessionId(sessionId)
                .build();
        byte[] signature;
        try {
            signature = signMessage(payload);
        } catch (Exception e) {
            return Mono.error(new Exception(e.getMessage()));
        }
        return integrationAuth.cancel(CancelAuthRequest.newBuilder()
                .setAccessKeyId(accessKeyId)
                .setSignature(ByteString.copyFrom(signature))
                .setPayload(payload)
                .build())
                .map(response -> (CancelAuthResponsePayload) handleResponse(response));
    }
}
