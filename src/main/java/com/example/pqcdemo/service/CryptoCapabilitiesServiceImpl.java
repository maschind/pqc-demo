package com.example.pqcdemo.service;

import com.example.pqcdemo.config.KeystoreConfig;
import com.example.pqcdemo.model.CertificateInfo;
import com.example.pqcdemo.model.CryptoCapabilitiesResponse;
import com.example.pqcdemo.model.RuntimeInfo;
import com.example.pqcdemo.model.SecurityProviderInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
public class CryptoCapabilitiesServiceImpl implements CryptoCapabilitiesService {

    private static final Logger logger = LoggerFactory.getLogger(CryptoCapabilitiesServiceImpl.class);

    private static final Set<String> PQC_ALGORITHM_PREFIXES = new HashSet<String>();

    static {
        PQC_ALGORITHM_PREFIXES.add("ML-KEM");
        PQC_ALGORITHM_PREFIXES.add("ML-DSA");
        PQC_ALGORITHM_PREFIXES.add("MLKEM");
        PQC_ALGORITHM_PREFIXES.add("MLDSA");
        PQC_ALGORITHM_PREFIXES.add("Kyber");
        PQC_ALGORITHM_PREFIXES.add("Dilithium");
        PQC_ALGORITHM_PREFIXES.add("SPHINCS");
        PQC_ALGORITHM_PREFIXES.add("Falcon");
    }

    @Autowired
    private KeystoreConfig keystoreConfig;

    @Override
    public CryptoCapabilitiesResponse getCapabilities() {
        logger.info("Building crypto capabilities response");

        CryptoCapabilitiesResponse response = new CryptoCapabilitiesResponse();
        response.setRuntime(buildRuntimeInfo());
        response.setSecurityProviders(buildSecurityProviders());
        response.setTls(buildTlsInfo());
        response.setServerCertificate(buildCertificateInfo());
        response.setPqc(buildPqcInfo());

        return response;
    }

    private RuntimeInfo buildRuntimeInfo() {
        RuntimeInfo info = new RuntimeInfo();
        info.setJavaVersion(System.getProperty("java.version"));
        info.setJavaVendor(System.getProperty("java.vendor"));
        info.setJavaVmName(System.getProperty("java.vm.name"));
        info.setOsName(System.getProperty("os.name"));
        info.setOsArch(System.getProperty("os.arch"));
        return info;
    }

    private List<SecurityProviderInfo> buildSecurityProviders() {
        Provider[] providers = Security.getProviders();
        List<SecurityProviderInfo> providerList = new ArrayList<SecurityProviderInfo>();

        for (int i = 0; i < providers.length; i++) {
            Provider provider = providers[i];
            SecurityProviderInfo providerInfo = new SecurityProviderInfo();
            providerInfo.setName(provider.getName());
            providerInfo.setVersion(provider.getVersionStr());
            providerInfo.setInfo(provider.getInfo());
            providerList.add(providerInfo);
        }

        return providerList;
    }

    private Map<String, Object> buildTlsInfo() {
        Map<String, Object> tls = new HashMap<String, Object>();

        try {
            SSLContext sslContext = SSLContext.getDefault();
            tls.put("defaultSslContextProvider", sslContext.getProvider().getName());

            SSLParameters defaultParams = sslContext.getDefaultSSLParameters();
            SSLParameters supportedParams = sslContext.getSupportedSSLParameters();

            String[] supportedProtocols = supportedParams.getProtocols();
            List<String> supportedProtocolList = new ArrayList<String>();
            for (int i = 0; i < supportedProtocols.length; i++) {
                supportedProtocolList.add(supportedProtocols[i]);
            }
            tls.put("supportedProtocols", supportedProtocolList);

            String[] enabledProtocols = defaultParams.getProtocols();
            List<String> enabledProtocolList = new ArrayList<String>();
            for (int i = 0; i < enabledProtocols.length; i++) {
                enabledProtocolList.add(enabledProtocols[i]);
            }
            tls.put("enabledProtocols", enabledProtocolList);

            String[] supportedCiphers = supportedParams.getCipherSuites();
            List<String> supportedCipherList = new ArrayList<String>();
            for (int i = 0; i < supportedCiphers.length; i++) {
                supportedCipherList.add(supportedCiphers[i]);
            }
            tls.put("supportedCipherSuites", supportedCipherList);

            String[] enabledCiphers = defaultParams.getCipherSuites();
            List<String> enabledCipherList = new ArrayList<String>();
            for (int i = 0; i < enabledCiphers.length; i++) {
                enabledCipherList.add(enabledCiphers[i]);
            }
            tls.put("enabledCipherSuites", enabledCipherList);

            Map<String, Object> namedGroups = new HashMap<String, Object>();
            String namedGroupsProp = Security.getProperty("jdk.tls.namedGroups");
            if (namedGroupsProp == null || namedGroupsProp.isEmpty()) {
                namedGroupsProp = System.getProperty("jdk.tls.namedGroups");
            }
            if (namedGroupsProp != null && !namedGroupsProp.isEmpty()) {
                String[] groups = namedGroupsProp.split(",");
                List<String> groupList = new ArrayList<String>();
                for (int i = 0; i < groups.length; i++) {
                    groupList.add(groups[i].trim());
                }
                namedGroups.put("supported", groupList);
                namedGroups.put("enabled", groupList);
            } else {
                namedGroups.put("supported", new ArrayList<String>());
                namedGroups.put("enabled", new ArrayList<String>());
            }
            namedGroups.put("note",
                    "Named groups depend on jdk.tls.namedGroups system property; defaults are provider-specific.");
            tls.put("namedGroups", namedGroups);

        } catch (Exception e) {
            logger.error("Failed to retrieve TLS info", e);
            tls.put("error", "Failed to retrieve TLS info: " + e.getMessage());
        }

        return tls;
    }

    private CertificateInfo buildCertificateInfo() {
        CertificateInfo certInfo = new CertificateInfo();

        try {
            String keystorePath = keystoreConfig.getKeystorePath();
            String keystorePassword = keystoreConfig.getKeystorePassword();
            String keystoreAlias = keystoreConfig.getKeystoreAlias();

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            InputStream inputStream = new FileInputStream(keystorePath);
            try {
                keyStore.load(inputStream, keystorePassword.toCharArray());
            } finally {
                inputStream.close();
            }

            X509Certificate cert = (X509Certificate) keyStore.getCertificate(keystoreAlias);
            if (cert == null) {
                logger.warn("Certificate not found for alias: {}", keystoreAlias);
                return certInfo;
            }

            certInfo.setSubject(cert.getSubjectX500Principal().getName());
            certInfo.setIssuer(cert.getIssuerX500Principal().getName());
            certInfo.setNotBefore(cert.getNotBefore().toString());
            certInfo.setNotAfter(cert.getNotAfter().toString());

            PublicKey publicKey = cert.getPublicKey();
            String algorithm = publicKey.getAlgorithm();
            certInfo.setPublicKeyAlgorithm(algorithm);

            int keySize = 0;
            if (publicKey instanceof RSAPublicKey) {
                RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
                keySize = rsaKey.getModulus().bitLength();
            } else if (publicKey instanceof ECPublicKey) {
                ECPublicKey ecKey = (ECPublicKey) publicKey;
                keySize = ecKey.getParams().getCurve().getField().getFieldSize();
            }
            certInfo.setPublicKeySizeBits(keySize);

            certInfo.setSignatureAlgorithm(cert.getSigAlgName());

            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                List<String> sanList = new ArrayList<String>();
                for (List<?> san : sans) {
                    Integer type = (Integer) san.get(0);
                    String value = san.get(1).toString();
                    String prefix;
                    if (type.intValue() == 2) {
                        prefix = "DNS:";
                    } else if (type.intValue() == 7) {
                        prefix = "IP:";
                    } else {
                        prefix = "OTHER:";
                    }
                    sanList.add(prefix + value);
                }
                certInfo.setSan(sanList);
            }

        } catch (Exception e) {
            logger.error("Failed to load certificate info", e);
        }

        return certInfo;
    }

    private Map<String, Object> buildPqcInfo() {
        Map<String, Object> pqc = new HashMap<String, Object>();

        boolean pqcPresent = false;
        Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {
            Provider provider = providers[i];
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                String algorithm = service.getAlgorithm().toUpperCase();
                for (String prefix : PQC_ALGORITHM_PREFIXES) {
                    if (algorithm.contains(prefix.toUpperCase())) {
                        pqcPresent = true;
                        break;
                    }
                }
                if (pqcPresent) {
                    break;
                }
            }
            if (pqcPresent) {
                break;
            }
        }

        pqc.put("presentInDefaultProviders", Boolean.valueOf(pqcPresent));
        pqc.put("note",
                "Java 17 default providers do not include standardized PQC algorithms (e.g., ML-KEM/ML-DSA).");

        return pqc;
    }
}
