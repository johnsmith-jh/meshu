package meshu.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.util.Set;

@SpringBootApplication
@ConfigurationPropertiesScan
public class MeshuGatewayApplication {

    /** Subcommands that run a CLI task and must exit — no web server. */
    private static final Set<String> CLI_COMMANDS = Set.of("self-info", "mint-ops", "bench-ping");

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(MeshuGatewayApplication.class);
        boolean cliOnly = java.util.Arrays.stream(args).anyMatch(CLI_COMMANDS::contains);
        if (cliOnly) {
            // Without this, Tomcat's non-daemon threads keep the JVM alive after
            // the runner finishes and the CLI hangs forever.
            app.setWebApplicationType(WebApplicationType.NONE);
        }
        app.run(args);
    }
}
