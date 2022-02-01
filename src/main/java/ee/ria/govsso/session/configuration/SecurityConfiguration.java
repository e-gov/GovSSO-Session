package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.configuration.properties.SecurityConfigurationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Slf4j
@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final SecurityConfigurationProperties securityConfigurationProperties;

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .securityContext().disable()
                .anonymous().disable()
                .logout().disable()
                .rememberMe().disable()
                .servletApi().disable()
                .httpBasic().disable()
                .sessionManagement().disable()
                .csrf().disable()
                .headers()
                .xssProtection().xssProtectionEnabled(false)
                .and()
                .frameOptions().deny()
                .contentSecurityPolicy(securityConfigurationProperties.getContentSecurityPolicy())
                .and()
                .httpStrictTransportSecurity()
                .includeSubDomains(true)
                .maxAgeInSeconds(186 * 24 * 60 * 60);
    }
}
