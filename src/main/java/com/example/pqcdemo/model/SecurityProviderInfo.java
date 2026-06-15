package com.example.pqcdemo.model;

import java.util.Objects;

public class SecurityProviderInfo {

    private String name;
    private String version;
    private String info;

    public SecurityProviderInfo() {
    }

    public SecurityProviderInfo(String name, String version, String info) {
        this.name = name;
        this.version = version;
        this.info = info;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getInfo() {
        return info;
    }

    public void setInfo(String info) {
        this.info = info;
    }

    @Override
    public String toString() {
        return "SecurityProviderInfo{" +
                "name='" + name + '\'' +
                ", version='" + version + '\'' +
                ", info='" + info + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityProviderInfo that = (SecurityProviderInfo) o;
        return Objects.equals(name, that.name) &&
                Objects.equals(version, that.version) &&
                Objects.equals(info, that.info);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, version, info);
    }
}
