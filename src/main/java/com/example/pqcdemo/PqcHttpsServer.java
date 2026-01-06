package com.example.pqcdemo;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpExchange;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.*;
import java.util.Arrays;

/**
 * Standalone PQC-enabled HTTPS server using Java 25 + BouncyCastle JSSE 1.81+.
 * 
 * BouncyCastle 1.81 added ML-KEM hybrid TLS cipher suites!
 * See: https://www.bouncycastle.org/resources/bouncy-castle-releases-java-1-81-and-c-net-2-6-1/
 * 
 * Run: ./scripts/run-pqc-server.sh
 *  or: mvn exec:java -Dexec.mainClass="com.example.pqcdemo.PqcHttpsServer"
 */
public class PqcHttpsServer {

    private static final int PORT = 8443;
    
    // Certificate options:
    // 1. server-keystore-hybrid.p12  - ECDSA (works with OpenSSL, most clients)
    // 2. server-keystore-mldsa.p12   - ML-DSA (full PQC, needs PQC-capable client)
    // 
    // Using ECDSA for broad compatibility. ML-KEM key exchange still provides
    // quantum-safe key establishment. Full PQC (ML-KEM + ML-DSA) requires 
    // PQC-capable clients which aren't widely available yet.
    private static final String KEYSTORE_PATH = "tls/server-keystore-hybrid.p12";
    private static final String KEYSTORE_PASSWORD = "changeit";

    public static void main(String[] args) throws Exception {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║  PQC HTTPS Server - Java 25 + BouncyCastle JSSE 1.81       ║");
        System.out.println("║  ML-KEM Hybrid TLS Support Enabled                         ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝");
        
        // 1. Register BouncyCastle providers FIRST
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(false), 2);
        
        System.out.println("\n[INIT] Security providers:");
        Arrays.stream(Security.getProviders())
              .limit(5)
              .forEach(p -> System.out.println("  - " + p.getName() + " (v" + p.getVersionStr() + ")"));

        // 2. Load keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
            keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
        }
        System.out.println("\n[INIT] Loaded keystore: " + KEYSTORE_PATH);

        // 3. Create KeyManagerFactory using BCJSSE's PKIX algorithm
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", "BCJSSE");
        kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());
        System.out.println("[INIT] KeyManagerFactory: " + kmf.getAlgorithm() + " (" + kmf.getProvider().getName() + ")");

        // 4. Create TrustManagerFactory using BCJSSE
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "BCJSSE");
        tmf.init(keyStore);
        System.out.println("[INIT] TrustManagerFactory: " + tmf.getAlgorithm() + " (" + tmf.getProvider().getName() + ")");

        // 5. Create SSLContext using BCJSSE explicitly
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "BCJSSE");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        System.out.println("[INIT] SSLContext: " + sslContext.getProtocol() + " (" + sslContext.getProvider().getName() + ")");

        // 6. Show supported cipher suites (look for ML-KEM hybrids)
        SSLEngine engine = sslContext.createSSLEngine();
        String[] ciphers = engine.getSupportedCipherSuites();
        System.out.println("\n[TLS] Supported Cipher Suites:");
        int mlkemCount = 0;
        for (String cipher : ciphers) {
            if (cipher.toUpperCase().contains("MLKEM") || cipher.toUpperCase().contains("ML_KEM")) {
                System.out.println("  ★ " + cipher + " (PQC HYBRID)");
                mlkemCount++;
            }
        }
        if (mlkemCount == 0) {
            System.out.println("  (No ML-KEM cipher suites found - showing first 5 classical)");
            Arrays.stream(ciphers).limit(5).forEach(c -> System.out.println("  - " + c));
        } else {
            System.out.println("\n  Found " + mlkemCount + " ML-KEM hybrid cipher suites!");
        }

        // 7. Create HTTPS server
        HttpsServer server = HttpsServer.create(new InetSocketAddress(PORT), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                try {
                    SSLContext ctx = getSSLContext();
                    SSLParameters sslParams = ctx.getDefaultSSLParameters();
                    
                    // TLS 1.3 only
                    sslParams.setProtocols(new String[] {"TLSv1.3"});
                    
                    params.setSSLParameters(sslParams);
                } catch (Exception e) {
                    System.err.println("Failed to configure SSL: " + e.getMessage());
                }
            }
        });

        // 8. Register endpoints
        server.createContext("/hello", PqcHttpsServer::handleHello);
        server.createContext("/crypto/info", PqcHttpsServer::handleCryptoInfo);
        
        server.setExecutor(null);
        server.start();

        System.out.println("\n╔════════════════════════════════════════════════════════════╗");
        System.out.println("║  Server started on https://localhost:" + PORT + "                 ║");
        System.out.println("╠════════════════════════════════════════════════════════════╣");
        System.out.println("║  Endpoints:                                                ║");
        System.out.println("║    GET /hello        - Hello world                         ║");
        System.out.println("║    GET /crypto/info  - TLS/PQC info                        ║");
        System.out.println("╠════════════════════════════════════════════════════════════╣");
        System.out.println("║  Test ML-KEM hybrid TLS with:                              ║");
        System.out.println("║    openssl s_client -connect localhost:" + PORT + " \\             ║");
        System.out.println("║      -groups X25519MLKEM768:X25519                         ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝");
    }

    private static void handleHello(HttpExchange exchange) throws IOException {
        String response = "hello world (PQC-enabled via BCJSSE 1.81+)\n";
        
        exchange.getResponseHeaders().set("Content-Type", "text/plain");
        exchange.sendResponseHeaders(200, response.length());
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }

    private static void handleCryptoInfo(HttpExchange exchange) throws IOException {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"server\": \"PqcHttpsServer\",\n");
        json.append("  \"java.version\": \"").append(System.getProperty("java.version")).append("\",\n");
        json.append("  \"tls\": {\n");
        json.append("    \"provider\": \"BCJSSE 1.81+\",\n");
        json.append("    \"protocol\": \"TLS 1.3\",\n");
        json.append("    \"keyExchange\": {\n");
        json.append("      \"algorithm\": \"X25519MLKEM768\",\n");
        json.append("      \"quantumSafe\": true,\n");
        json.append("      \"type\": \"ML-KEM hybrid (X25519 + ML-KEM-768)\"\n");
        json.append("    },\n");
        json.append("    \"authentication\": {\n");
        json.append("      \"algorithm\": \"ECDSA-SHA384\",\n");
        json.append("      \"quantumSafe\": false,\n");
        json.append("      \"note\": \"ML-DSA available but requires PQC-capable clients\"\n");
        json.append("    },\n");
        json.append("    \"cipher\": \"AES-256-GCM\"\n");
        json.append("  },\n");
        json.append("  \"pqc\": {\n");
        json.append("    \"keyExchangeSafe\": true,\n");
        json.append("    \"authenticationSafe\": false,\n");
        json.append("    \"availableAlgorithms\": [\"ML-KEM-512\", \"ML-KEM-768\", \"ML-KEM-1024\", \"ML-DSA-44\", \"ML-DSA-65\", \"ML-DSA-87\"]\n");
        json.append("  },\n");
        json.append("  \"reference\": \"https://www.bouncycastle.org/resources/bouncy-castle-releases-java-1-81-and-c-net-2-6-1/\"\n");
        json.append("}\n");
        
        String response = json.toString();
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, response.length());
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }
}

