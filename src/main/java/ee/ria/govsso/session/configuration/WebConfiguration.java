package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.session.SsoCookieArgumentResolver;
import ee.ria.govsso.session.session.SsoCookieSigner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Slf4j
@EnableRetry
@EnableScheduling
@ConfigurationPropertiesScan
@Configuration
@RequiredArgsConstructor
public class WebConfiguration implements WebMvcConfigurer {
    private final ConfigurableBeanFactory configurableBeanFactory;
    private final SsoCookieSigner ssoCookieSigner;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(new SsoCookieArgumentResolver(configurableBeanFactory, ssoCookieSigner));
    }
}
