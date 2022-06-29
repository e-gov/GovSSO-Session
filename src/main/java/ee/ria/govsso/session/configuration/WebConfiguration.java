package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.session.SsoCookieArgumentResolver;
import ee.ria.govsso.session.session.SsoCookieSigner;
import ee.ria.govsso.session.util.LocaleUtil;
import ee.ria.govsso.session.util.SupportedLocaleContextResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

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

    @Bean
    public LocaleResolver localeResolver() {
        CookieLocaleResolver resolver = new CookieLocaleResolver();
        resolver.setCookieName("__Host-LOCALE");
        resolver.setCookieSecure(true);
        resolver.setCookieMaxAge(10 * 365 * 24 * 60 * 60);

        // Setting default locale prevents CookieLocaleResolver from falling back to request.getLocale()
        resolver.setDefaultLocale(LocaleUtil.DEFAULT_LOCALE);

        return new SupportedLocaleContextResolver(resolver, LocaleUtil.SUPPORTED_LOCALES, LocaleUtil.DEFAULT_LOCALE);
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor lci = new LocaleChangeInterceptor();
        lci.setParamName("lang");
        return lci;
    }

    @Bean
    public MessageSource messageSource() {
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasename("messages");
        messageSource.setDefaultEncoding("UTF-8");
        messageSource.setDefaultLocale(LocaleUtil.DEFAULT_LOCALE);
        return messageSource;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor());
    }
}
