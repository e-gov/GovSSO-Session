package ee.ria.govsso.session;

import co.elastic.apm.attach.ElasticApmAttacher;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;

@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
public class Application {

    public static void main(String[] args) {
        ElasticApmAttacher.attach();
        SpringApplication.run(Application.class, args);
    }
}
