package com.example.pqcdemo;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Path("/crypto")
public class CryptoCapabilitiesResource {

    private static final String KEYSTORE_PATH = "tls/server-keystore.p12";
    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String KEYSTORE_ALIAS = "server";

    private static final Set<String> PQC_ALGORITHM_PREFIXES = Set.of(
            "ML-KEM", "ML-DSA", "MLKEM", "MLDSA", "Kyber", "Dilithium", "SPHINCS", "Falcon"
    );

    @GET
    @Path("/capabilities")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> getCapabilities() {
        Map<String, Object> result = new LinkedHashMap<>();

        // Runtime info
        result.put("runtime", buildRuntimeInfo());

        // Security providers
        result.put("securityProviders", buildSecurityProviders());

        // TLS info
        result.put("tls", buildTlsInfo());

        // Server certificate info
        result.put("serverCertificate", buildServerCertificateInfo());

        // PQC info
        result.put("pqc", buildPqcInfo());

        return result;
    }

    private Map<String, Object> buildRuntimeInfo() {
        Map<String, Object> runtime = new LinkedHashMap<>();
        runtime.put("javaVersion", System.getProperty("java.version"));
        runtime.put("javaVendor", System.getProperty("java.vendor"));
        runtime.put("javaVmName", System.getProperty("java.vm.name"));
        runtime.put("osName", System.getProperty("os.name"));
        runtime.put("osArch", System.getProperty("os.arch"));
        return runtime;
    }

    private List<Map<String, Object>> buildSecurityProviders() {
        List<Map<String, Object>> providers = new ArrayList<>();
        for (Provider provider : Security.getProviders()) {
            Map<String, Object> providerInfo = new LinkedHashMap<>();
            providerInfo.put("name", provider.getName());
            providerInfo.put("version", provider.getVersionStr());
            providerInfo.put("info", provider.getInfo());
            providers.add(providerInfo);
        }
        return providers;
    }

    private Map<String, Object> buildTlsInfo() {
        Map<String, Object> tls = new LinkedHashMap<>();

        try {
            SSLContext sslContext = SSLContext.getDefault();
            tls.put("defaultSslContextProvider", sslContext.getProvider().getName());

            SSLParameters defaultParams = sslContext.getDefaultSSLParameters();
            SSLParameters supportedParams = sslContext.getSupportedSSLParameters();

            tls.put("supportedProtocols", Arrays.asList(supportedParams.getProtocols()));
            tls.put("enabledProtocols", Arrays.asList(defaultParams.getProtocols()));
            tls.put("supportedCipherSuites", Arrays.asList(supportedParams.getCipherSuites()));
            tls.put("enabledCipherSuites", Arrays.asList(defaultParams.getCipherSuites()));

            // Named groups
            Map<String, Object> namedGroups = new LinkedHashMap<>();
            String namedGroupsProp = System.getProperty("jdk.tls.namedGroups");
            if (namedGroupsProp != null && !namedGroupsProp.isEmpty()) {
                namedGroups.put("supported", Arrays.asList(namedGroupsProp.split(",")));
                namedGroups.put("enabled", Arrays.asList(namedGroupsProp.split(",")));
            } else {
                namedGroups.put("supported", Collections.emptyList());
                namedGroups.put("enabled", Collections.emptyList());
            }
            namedGroups.put("note", "Named groups depend on jdk.tls.namedGroups system property; defaults are provider-specific.");
            tls.put("namedGroups", namedGroups);

        } catch (Exception e) {
            tls.put("error", "Failed to retrieve TLS info: " + e.getMessage());
        }

        return tls;
    }

    private Map<String, Object> buildServerCertificateInfo() {
        Map<String, Object> certInfo = new LinkedHashMap<>();

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
                keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
            }

            X509Certificate cert = (X509Certificate) keyStore.getCertificate(KEYSTORE_ALIAS);
            if (cert == null) {
                certInfo.put("error", "Certificate not found for alias: " + KEYSTORE_ALIAS);
                return certInfo;
            }

            certInfo.put("subject", cert.getSubjectX500Principal().getName());
            certInfo.put("issuer", cert.getIssuerX500Principal().getName());
            certInfo.put("notBefore", cert.getNotBefore().toString());
            certInfo.put("notAfter", cert.getNotAfter().toString());

            // Public key info
            java.security.PublicKey pubKey = cert.getPublicKey();
            String algorithm = pubKey.getAlgorithm();
            certInfo.put("publicKeyAlgorithm", algorithm);

            int keySize = 0;
            if (pubKey instanceof RSAPublicKey rsaKey) {
                keySize = rsaKey.getModulus().bitLength();
            } else if (pubKey instanceof ECPublicKey ecKey) {
                keySize = ecKey.getParams().getCurve().getField().getFieldSize();
            }
            certInfo.put("publicKeySizeBits", keySize);

            certInfo.put("signatureAlgorithm", cert.getSigAlgName());

            // Subject Alternative Names
            List<String> sanList = new ArrayList<>();
            var sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    int type = (Integer) san.get(0);
                    String value = san.get(1).toString();
                    String prefix = switch (type) {
                        case 2 -> "DNS:";
                        case 7 -> "IP:";
                        default -> "OTHER:";
                    };
                    sanList.add(prefix + value);
                }
            }
            certInfo.put("san", sanList);

        } catch (Exception e) {
            certInfo.put("error", "Failed to load certificate: " + e.getMessage());
        }

        return certInfo;
    }

    private Map<String, Object> buildPqcInfo() {
        Map<String, Object> pqc = new LinkedHashMap<>();

        boolean pqcPresent = false;
        for (Provider provider : Security.getProviders()) {
            for (Provider.Service service : provider.getServices()) {
                String algorithm = service.getAlgorithm().toUpperCase();
                for (String prefix : PQC_ALGORITHM_PREFIXES) {
                    if (algorithm.contains(prefix.toUpperCase())) {
                        pqcPresent = true;
                        break;
                    }
                }
                if (pqcPresent) break;
            }
            if (pqcPresent) break;
        }

        pqc.put("presentInDefaultProviders", pqcPresent);
        pqc.put("note", "Java 17 default providers do not include standardized PQC algorithms (e.g., ML-KEM/ML-DSA).");

        return pqc;
    }
}
