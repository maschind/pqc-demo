package com.example.pqcdemo;

import io.quarkus.runtime.Startup;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.jboss.logging.Logger;

import java.security.Security;

/**
 * Initializes BouncyCastle security providers for PQC support.
 * 
 * This is a WORKAROUND until JEP 527 (Hybrid Key Exchange for TLS) is available.
 * See: https://bugs.openjdk.org/browse/JDK-8369848
 * 
 * BouncyCastle provides:
 * - bcprov: Core cryptographic provider (including PQC algorithms like ML-KEM, ML-DSA)
 * - bctls: TLS provider with PQC hybrid key exchange support
 */
@Startup
@ApplicationScoped
public class BouncyCastleInitializer {

    private static final Logger LOG = Logger.getLogger(BouncyCastleInitializer.class);

    @PostConstruct
    void init() {
        LOG.info("Initializing BouncyCastle PQC providers (JEP 527 workaround)...");
        
        // Register BouncyCastle providers
        // Order matters: insert at specific positions for proper provider chain
        
        // 1. Core BouncyCastle provider (general crypto + PQC algorithms)
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
            LOG.info("Registered BouncyCastleProvider at position 1");
        }
        
        // 2. BouncyCastle JSSE provider (TLS with PQC support)
        if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
            LOG.info("Registered BouncyCastleJsseProvider at position 2");
        }
        
        LOG.info("BouncyCastle PQC providers initialized successfully");
        LOG.info("PQC algorithms available: Kyber, Dilithium, SPHINCS+, Falcon, etc.");
        LOG.info("TLS hybrid key exchange: Supported via BouncyCastle JSSE");
    }
}

