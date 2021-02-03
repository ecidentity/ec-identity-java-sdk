package io.ecidentity.integration.client;

import com.google.protobuf.AbstractMessage;
import com.google.protobuf.ByteString;
import io.ecidentity.integration.utils.Config;
import io.ecidentity.protocol.authority.CertificateRequest;
import io.ecidentity.protocol.authority.CertificateResponse;
import io.ecidentity.protocol.authority.IntegrationTrustServiceGrpc;
import io.ecidentity.protocol.types.ResultCodeExtProtocol;
import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import static io.ecidentity.integration.utils.CryptoUtils.*;
import static io.ecidentity.integration.utils.MessageUtils.*;

public class ClientBase {

    private final IntegrationTrustServiceGrpc.IntegrationTrustServiceBlockingStub integrationTrust;
    private final KeyStore keyStore;
    private final char[] password;

    private X509Certificate certificate;

    protected final ManagedChannel authorityChannel;

    public ClientBase(Config config, KeyStore keyStore, char[] password) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        this.keyStore = keyStore;
        this.password = password;

        authorityChannel = NettyChannelBuilder.forAddress(config.host, config.port)
                .useTransportSecurity()
                .build();

        integrationTrust = IntegrationTrustServiceGrpc.newBlockingStub(authorityChannel);

        retrieveCertificate();
    }

    protected byte[] signMessage(AbstractMessage message) throws NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, KeyStoreException, InvalidKeyException {
        return signHash(sha256(message.toByteArray()));
    }

    protected AbstractMessage handlePayload(AbstractMessage response) throws Exception {
        if (new Date().after(certificate.getNotAfter())) {
            retrieveCertificate();
        }
        AbstractMessage payload = getPayload(response);
        verifyMessage(getSignature(response), payload);
        return response;
    }

    protected AbstractMessage handleResponse(AbstractMessage response) {
        try {
            if (new Date().after(certificate.getNotAfter())) {
                retrieveCertificate();
            }
            AbstractMessage payload = getPayload(response);
            ResultCodeExtProtocol resultCode = getResultCode(payload);
            verifyMessage(getSignature(response), payload);
            switch (resultCode) {
                case OK:
                case PENDING:
                    return payload;
                default:
                    throw new RuntimeException("Result: " + resultCode.name());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void verifyMessage(ByteString signature, AbstractMessage message) throws Exception {
        if (new Date().after(certificate.getNotAfter())) retrieveCertificate();
        if (!verify(sha256(message.toByteArray()), certificate.getPublicKey(), signature.toByteArray()))
            throw new Exception("Invalid signature");
    }

    private byte[] signHash(byte[] hash) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, SignatureException, InvalidKeyException {
        if (hash.length != 32) throw new IllegalArgumentException("Invalid hash size, must be 32 bytes");
        return sign(hash, (PrivateKey) keyStore.getKey("client", password));
    }

    private void retrieveCertificate() throws SecurityException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        CertificateResponse response = integrationTrust.cert(CertificateRequest.newBuilder().build());
        X509Certificate newCertificate = decodeX509Certificate(response.getPayload().getServerCertificate().toByteArray());
        if (verify(sha256(response.getPayload().toByteArray()), newCertificate.getPublicKey(), response.getSignature().toByteArray())
                && response.getPayload().getResultCode() == ResultCodeExtProtocol.OK) {
            certificate = newCertificate;
        } else throw new SecurityException("Certificate error");
    }

    public void shutdown() {
        authorityChannel.shutdown();
    }
}