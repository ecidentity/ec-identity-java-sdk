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

public class ReactorSignClient extends ClientBase {

    public static class Builder{

        private final Config config;
        private String accessKeyId;
        private KeyStore keyStore;
        private char[] password;

        public Builder(Config config){
            this.config = config;
        }

        public Builder withAccessKey(String accessKey){
            this.accessKeyId = accessKey;
            return this;
        }

        public Builder withKeyStore(KeyStore keyStore){
            this.keyStore = keyStore;
            return this;
        }

        public Builder withPassword(char[] password){
            this.password = password;
            return this;
        }

        public ReactorSignClient build() throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
            return new ReactorSignClient(accessKeyId, keyStore, password, config);
        }
    }

    private final ReactorIntegrationSignServiceGrpc.ReactorIntegrationSignServiceStub integrationSign;
    private final String accessKeyId;

    private ReactorSignClient(String accessKeyId, KeyStore keyStore, char[] password, Config config) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException {
        super(config, keyStore, password);

        this.integrationSign = ReactorIntegrationSignServiceGrpc.newReactorStub(authorityChannel);
        this.accessKeyId = accessKeyId;
    }

    public Flux<InitSignResponsePayload> init(String email, KeyEntryTypeProtocol type) {
        InitSignRequestPayload payload = InitSignRequestPayload.newBuilder()
                .setEmail(email)
                .setType(type)
                .build();
        byte[] signature;
        try {
            signature = signMessage(payload);
        } catch (Exception e) {
            return Flux.error(new Exception(e.getMessage()));
        }
        return integrationSign.init(InitSignRequest.newBuilder()
                .setAccessKeyId(accessKeyId)
                .setSignature(ByteString.copyFrom(signature))
                .setPayload(payload)
                .build())
                .map(response -> (InitSignResponsePayload) handleResponse(response))
                .takeUntil(result -> getResultCode(result) != ResultCodeExtProtocol.PENDING);
    }

    public Flux<SignHashResponsePayload> hash(String sessionId, byte[] hash) {
        SignHashRequestPayload payload = SignHashRequestPayload.newBuilder()
                .setSessionId(sessionId)
                .setHashToSign(ByteString.copyFrom(hash))
                .build();
        byte[] signature;
        try {
            signature = signMessage(payload);
        } catch (Exception e) {
            return Flux.error(new Exception(e.getMessage()));
        }
        return integrationSign.hash(SignHashRequest.newBuilder()
                .setAccessKeyId(accessKeyId)
                .setSignature(ByteString.copyFrom(signature))
                .setPayload(payload)
                .build())
                .map(response -> (SignHashResponsePayload) handleResponse(response))
                .takeUntil(result -> getResultCode(result) != ResultCodeExtProtocol.PENDING);
    }

    public Mono<CancelSignResponsePayload> cancel(String sessionId) {
        CancelSignRequestPayload payload = CancelSignRequestPayload.newBuilder()
                .setSessionId(sessionId)
                .build();
        byte[] signature;
        try {
            signature = signMessage(payload);
        } catch (Exception e) {
            return Mono.error(new Exception(e.getMessage()));
        }
        return integrationSign.cancel(CancelSignRequest.newBuilder()
                .setAccessKeyId(accessKeyId)
                .setSignature(ByteString.copyFrom(signature))
                .setPayload(payload)
                .build())
                .map(response -> (CancelSignResponsePayload) handleResponse(response));

    }
}