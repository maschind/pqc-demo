package com.example.pqcdemo.model;

import java.util.Objects;

public class RuntimeInfo {

    private String javaVersion;
    private String javaVendor;
    private String javaVmName;
    private String osName;
    private String osArch;

    public RuntimeInfo() {
    }

    public RuntimeInfo(String javaVersion, String javaVendor, String javaVmName,
                       String osName, String osArch) {
        this.javaVersion = javaVersion;
        this.javaVendor = javaVendor;
        this.javaVmName = javaVmName;
        this.osName = osName;
        this.osArch = osArch;
    }

    public String getJavaVersion() {
        return javaVersion;
    }

    public void setJavaVersion(String javaVersion) {
        this.javaVersion = javaVersion;
    }

    public String getJavaVendor() {
        return javaVendor;
    }

    public void setJavaVendor(String javaVendor) {
        this.javaVendor = javaVendor;
    }

    public String getJavaVmName() {
        return javaVmName;
    }

    public void setJavaVmName(String javaVmName) {
        this.javaVmName = javaVmName;
    }

    public String getOsName() {
        return osName;
    }

    public void setOsName(String osName) {
        this.osName = osName;
    }

    public String getOsArch() {
        return osArch;
    }

    public void setOsArch(String osArch) {
        this.osArch = osArch;
    }

    @Override
    public String toString() {
        return "RuntimeInfo{" +
                "javaVersion='" + javaVersion + '\'' +
                ", javaVendor='" + javaVendor + '\'' +
                ", javaVmName='" + javaVmName + '\'' +
                ", osName='" + osName + '\'' +
                ", osArch='" + osArch + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RuntimeInfo that = (RuntimeInfo) o;
        return Objects.equals(javaVersion, that.javaVersion) &&
                Objects.equals(javaVendor, that.javaVendor) &&
                Objects.equals(javaVmName, that.javaVmName) &&
                Objects.equals(osName, that.osName) &&
                Objects.equals(osArch, that.osArch);
    }

    @Override
    public int hashCode() {
        return Objects.hash(javaVersion, javaVendor, javaVmName, osName, osArch);
    }
}
