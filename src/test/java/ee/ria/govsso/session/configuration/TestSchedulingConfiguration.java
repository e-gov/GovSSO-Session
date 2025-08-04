package ee.ria.govsso.session.configuration;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.support.NoOpTaskScheduler;

@TestConfiguration
public class TestSchedulingConfiguration {

    @Bean
    public TaskScheduler noOpTaskScheduler() {
        return new NoOpTaskScheduler();
    }

}
