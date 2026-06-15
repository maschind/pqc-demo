package com.example.pqcdemo.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeystoreConfig {

    @Value("${app.keystore.path}")
    private String keystorePath;

    @Value("${app.keystore.password}")
    private String keystorePassword;

    @Value("${app.keystore.alias}")
    private String keystoreAlias;

    public String getKeystorePath() {
        return keystorePath;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public String getKeystoreAlias() {
        return keystoreAlias;
    }
}
