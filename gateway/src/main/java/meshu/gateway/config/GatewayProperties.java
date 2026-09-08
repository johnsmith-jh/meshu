package meshu.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "meshu")
public record GatewayProperties(Serial serial, Mint mint) {

    public record Serial(String port, int baud) {
    }

    public record Mint(String url) {
    }
}
