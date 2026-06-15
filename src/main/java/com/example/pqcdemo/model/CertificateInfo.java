package com.example.pqcdemo.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class CertificateInfo {

    private String subject;
    private String issuer;
    private String notBefore;
    private String notAfter;
    private String publicKeyAlgorithm;
    private int publicKeySizeBits;
    private String signatureAlgorithm;
    private List<String> san;

    public CertificateInfo() {
        this.san = new ArrayList<String>();
    }

    public CertificateInfo(String subject, String issuer, String notBefore, String notAfter,
                           String publicKeyAlgorithm, int publicKeySizeBits,
                           String signatureAlgorithm, List<String> san) {
        this.subject = subject;
        this.issuer = issuer;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.publicKeySizeBits = publicKeySizeBits;
        this.signatureAlgorithm = signatureAlgorithm;
        this.san = san;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public String getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(String notAfter) {
        this.notAfter = notAfter;
    }

    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    public int getPublicKeySizeBits() {
        return publicKeySizeBits;
    }

    public void setPublicKeySizeBits(int publicKeySizeBits) {
        this.publicKeySizeBits = publicKeySizeBits;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public List<String> getSan() {
        return san;
    }

    public void setSan(List<String> san) {
        this.san = san;
    }

    @Override
    public String toString() {
        return "CertificateInfo{" +
                "subject='" + subject + '\'' +
                ", issuer='" + issuer + '\'' +
                ", notBefore='" + notBefore + '\'' +
                ", notAfter='" + notAfter + '\'' +
                ", publicKeyAlgorithm='" + publicKeyAlgorithm + '\'' +
                ", publicKeySizeBits=" + publicKeySizeBits +
                ", signatureAlgorithm='" + signatureAlgorithm + '\'' +
                ", san=" + san +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CertificateInfo that = (CertificateInfo) o;
        return publicKeySizeBits == that.publicKeySizeBits &&
                Objects.equals(subject, that.subject) &&
                Objects.equals(issuer, that.issuer) &&
                Objects.equals(notBefore, that.notBefore) &&
                Objects.equals(notAfter, that.notAfter) &&
                Objects.equals(publicKeyAlgorithm, that.publicKeyAlgorithm) &&
                Objects.equals(signatureAlgorithm, that.signatureAlgorithm) &&
                Objects.equals(san, that.san);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject, issuer, notBefore, notAfter,
                publicKeyAlgorithm, publicKeySizeBits, signatureAlgorithm, san);
    }
}
