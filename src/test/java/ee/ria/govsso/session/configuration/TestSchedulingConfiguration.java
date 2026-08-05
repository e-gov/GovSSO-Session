package ee.ria.govsso.session.configuration;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.support.NoOpTaskScheduler;

@AutoConfiguration
public class TestSchedulingConfiguration {

    @Bean
    public TaskScheduler noOpTaskScheduler() {
        return new NoOpTaskScheduler();
    }

}
