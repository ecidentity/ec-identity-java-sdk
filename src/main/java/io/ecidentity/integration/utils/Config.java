package io.ecidentity.integration.utils;

public enum Config {
    TEST("test-api.ecidentity.io", 1443),
    DEMO("demo-api.ecidentity.io", 1443),
    PROD("api.ecidentity.io", 1443);

    Config(String host, Integer port) {
        this.host = host;
        this.port = port;
    }

    public String host;
    public Integer port;
}
