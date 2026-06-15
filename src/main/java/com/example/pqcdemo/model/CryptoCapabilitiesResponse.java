package com.example.pqcdemo.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class CryptoCapabilitiesResponse {

    private RuntimeInfo runtime;
    private List<SecurityProviderInfo> securityProviders;
    private Map<String, Object> tls;
    private CertificateInfo serverCertificate;
    private Map<String, Object> pqc;

    public CryptoCapabilitiesResponse() {
        this.securityProviders = new ArrayList<SecurityProviderInfo>();
        this.tls = new HashMap<String, Object>();
        this.pqc = new HashMap<String, Object>();
    }

    public CryptoCapabilitiesResponse(RuntimeInfo runtime,
                                      List<SecurityProviderInfo> securityProviders,
                                      Map<String, Object> tls,
                                      CertificateInfo serverCertificate,
                                      Map<String, Object> pqc) {
        this.runtime = runtime;
        this.securityProviders = securityProviders;
        this.tls = tls;
        this.serverCertificate = serverCertificate;
        this.pqc = pqc;
    }

    public RuntimeInfo getRuntime() {
        return runtime;
    }

    public void setRuntime(RuntimeInfo runtime) {
        this.runtime = runtime;
    }

    public List<SecurityProviderInfo> getSecurityProviders() {
        return securityProviders;
    }

    public void setSecurityProviders(List<SecurityProviderInfo> securityProviders) {
        this.securityProviders = securityProviders;
    }

    public Map<String, Object> getTls() {
        return tls;
    }

    public void setTls(Map<String, Object> tls) {
        this.tls = tls;
    }

    public CertificateInfo getServerCertificate() {
        return serverCertificate;
    }

    public void setServerCertificate(CertificateInfo serverCertificate) {
        this.serverCertificate = serverCertificate;
    }

    public Map<String, Object> getPqc() {
        return pqc;
    }

    public void setPqc(Map<String, Object> pqc) {
        this.pqc = pqc;
    }

    @Override
    public String toString() {
        return "CryptoCapabilitiesResponse{" +
                "runtime=" + runtime +
                ", securityProviders=" + securityProviders +
                ", tls=" + tls +
                ", serverCertificate=" + serverCertificate +
                ", pqc=" + pqc +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CryptoCapabilitiesResponse that = (CryptoCapabilitiesResponse) o;
        return Objects.equals(runtime, that.runtime) &&
                Objects.equals(securityProviders, that.securityProviders) &&
                Objects.equals(tls, that.tls) &&
                Objects.equals(serverCertificate, that.serverCertificate) &&
                Objects.equals(pqc, that.pqc);
    }

    @Override
    public int hashCode() {
        return Objects.hash(runtime, securityProviders, tls, serverCertificate, pqc);
    }
}
