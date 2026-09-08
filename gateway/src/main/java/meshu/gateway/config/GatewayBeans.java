package meshu.gateway.config;

import meshu.gateway.mint.MintClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Bean wiring for the gateway daemon. */
@Configuration
public class GatewayBeans {

    /** The Cashu mint client, pointed at the configured mint URL. */
    @Bean
    public MintClient mintClient(GatewayProperties props) {
        return new MintClient(props.mint().url());
    }
}
