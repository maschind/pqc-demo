package com.example.pqcdemo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

/**
 * MIGRATION CHALLENGE — Hardcoded security properties:
 *
 * The static initializer below sets jdk.tls.disabledAlgorithms and
 * jdk.tls.namedGroups at application startup. This is a common enterprise
 * pattern — security teams mandate specific algorithm restrictions that
 * get baked into the application or deployment scripts.
 *
 * Problem for PQC migration:
 * - The disabledAlgorithms list was written for classical crypto only.
 *   On Java 25, new PQC algorithm names exist (ML-KEM, ML-DSA) that
 *   aren't in this list. That's fine for a deny-list — but if the
 *   enterprise security policy switches to an ALLOW-list approach
 *   (only these algorithms are permitted), PQC algorithms would be
 *   blocked until the policy is updated.
 * - The namedGroups list explicitly enumerates classical ECDHE curves.
 *   On Java 25, PQC/hybrid key exchange groups (e.g., x25519_ml-kem-768)
 *   must be added to this list, or they won't be negotiated even if the
 *   JVM supports them.
 * - These properties are often set in java.security policy files deployed
 *   across hundreds of servers. Changing them requires coordination with
 *   the security team, change management boards, and phased rollouts.
 */
@SpringBootApplication
public class PqcDemoApplication {

    private static final Logger logger = LoggerFactory.getLogger(PqcDemoApplication.class);

    static {
        // Enterprise security hardening — restrict TLS algorithms at startup
        // These are classical-only; PQC groups/algorithms are not included
        Security.setProperty("jdk.tls.disabledAlgorithms",
                "SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, "
                + "DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL");

        Security.setProperty("jdk.tls.namedGroups",
                "secp256r1, secp384r1, secp521r1, x25519, x448, "
                + "ffdhe2048, ffdhe3072, ffdhe4096");

        logger.info("Applied enterprise TLS security hardening — classical algorithms only");
    }

    public static void main(String[] args) {
        SpringApplication.run(PqcDemoApplication.class, args);
    }
}
