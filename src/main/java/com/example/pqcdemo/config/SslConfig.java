package com.example.pqcdemo.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Enterprise SSL configuration for outbound HTTPS connections.
 *
 * MIGRATION CHALLENGE #1 — Hardcoded TLS 1.2:
 * SSLContext.getInstance("TLSv1.2") pins the outbound protocol to TLS 1.2.
 * On Java 25, TLS 1.3 with PQC key exchange (ML-KEM hybrid) is available,
 * but this code prevents it. The fix is to use SSLContext.getInstance("TLS")
 * which negotiates the highest mutually-supported protocol — but enterprise
 * security teams often resist this because they want explicit protocol control.
 *
 * MIGRATION CHALLENGE #2 — Custom TrustManager:
 * The AuditTrustManager wraps the default trust manager to log certificate chains.
 * This pattern works for RSA/EC certificates, but when Java 25 introduces ML-DSA
 * certificates, the logging code that inspects key types via instanceof checks
 * (RSAPublicKey, ECPublicKey) won't recognize the new key types. They'll fall
 * through to "unknown" — not a crash, but a compliance gap in audit logs.
 */
@Configuration
public class SslConfig {

    private static final Logger logger = LoggerFactory.getLogger(SslConfig.class);

    @Bean
    public RestTemplate restTemplate() throws Exception {
        SSLContext sslContext = createHardenedSslContext();
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        logger.info("Configured RestTemplate with hardened TLS 1.2 SSLContext");
        return new RestTemplate();
    }

    private SSLContext createHardenedSslContext() throws Exception {
        // HARDCODED to TLS 1.2 — enterprise security policy requirement
        // This prevents TLS 1.3 negotiation and blocks PQC key exchange
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);

        TrustManager[] defaultTrustManagers = tmf.getTrustManagers();
        X509TrustManager defaultTrustManager = null;
        for (int i = 0; i < defaultTrustManagers.length; i++) {
            if (defaultTrustManagers[i] instanceof X509TrustManager) {
                defaultTrustManager = (X509TrustManager) defaultTrustManagers[i];
                break;
            }
        }

        if (defaultTrustManager == null) {
            throw new IllegalStateException("No X509TrustManager found in default trust managers");
        }

        TrustManager[] wrappedTrustManagers = new TrustManager[]{
                new AuditTrustManager(defaultTrustManager)
        };

        sslContext.init(null, wrappedTrustManagers, null);
        return sslContext;
    }

    /**
     * Custom TrustManager that wraps the default and adds audit logging.
     * Common enterprise pattern for compliance — "log every certificate chain we trust."
     *
     * Uses instanceof + explicit cast for key type detection (legacy Java pattern).
     * PQC key types (ML-DSA) won't be recognized by these checks.
     */
    private static class AuditTrustManager implements X509TrustManager {

        private static final Logger auditLogger = LoggerFactory.getLogger("com.example.pqcdemo.ssl.audit");

        private final X509TrustManager delegate;

        AuditTrustManager(X509TrustManager delegate) {
            this.delegate = delegate;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            auditLogger.debug("Checking client certificate chain, authType={}", authType);
            logCertificateChain(chain);
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            auditLogger.debug("Checking server certificate chain, authType={}", authType);
            logCertificateChain(chain);
            delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }

        private void logCertificateChain(X509Certificate[] chain) {
            if (chain == null) {
                return;
            }
            for (int i = 0; i < chain.length; i++) {
                X509Certificate cert = chain[i];
                String subject = cert.getSubjectX500Principal().getName();
                String keyAlgorithm = cert.getPublicKey().getAlgorithm();
                int keySize = 0;

                // instanceof + cast pattern — does not recognize PQC key types
                if (cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey) {
                    java.security.interfaces.RSAPublicKey rsaKey =
                            (java.security.interfaces.RSAPublicKey) cert.getPublicKey();
                    keySize = rsaKey.getModulus().bitLength();
                } else if (cert.getPublicKey() instanceof java.security.interfaces.ECPublicKey) {
                    java.security.interfaces.ECPublicKey ecKey =
                            (java.security.interfaces.ECPublicKey) cert.getPublicKey();
                    keySize = ecKey.getParams().getCurve().getField().getFieldSize();
                }

                auditLogger.info("  Certificate[{}]: subject={}, algorithm={}, keySize={}",
                        i, subject, keyAlgorithm, keySize);
            }
        }
    }
}
