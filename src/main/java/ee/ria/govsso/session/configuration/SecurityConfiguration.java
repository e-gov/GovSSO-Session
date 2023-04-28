package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.configuration.properties.SecurityConfigurationProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.header.HeaderWriter;

import static ee.ria.govsso.session.controller.AdminController.ADMIN_SESSIONS_BY_ID_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.AdminController.ADMIN_SESSIONS_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.ConsentInitController.CONSENT_INIT_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.LoginInitController.LOGIN_INIT_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.RefreshTokenHookController.TOKEN_REFRESH_REQUEST_MAPPING;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN;
import static org.springframework.http.HttpHeaders.ORIGIN;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {

    public static final String COOKIE_NAME_XSRF_TOKEN = "__Host-XSRF-TOKEN";
    private final SecurityConfigurationProperties securityConfigurationProperties;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .securityContext().disable()
                .anonymous().disable()
                .logout().disable()
                .rememberMe().disable()
                .servletApi().disable()
                .httpBasic().disable()
                .sessionManagement().disable()
                .csrf(csrf -> csrf
                        .ignoringAntMatchers(TOKEN_REFRESH_REQUEST_MAPPING, ADMIN_SESSIONS_REQUEST_MAPPING, ADMIN_SESSIONS_BY_ID_REQUEST_MAPPING)
                        .csrfTokenRepository(csrfTokenRepository()))
                .headers()
                .addHeaderWriter(relaxedCorsHeaderWriter())
                .xssProtection().xssProtectionEnabled(false)
                .and()
                .frameOptions().deny()
                .contentSecurityPolicy(securityConfigurationProperties.getContentSecurityPolicy())
                .and()
                .httpStrictTransportSecurity()
                .includeSubDomains(true)
                .maxAgeInSeconds(186 * 24 * 60 * 60);
        return httpSecurity.build();
    }

    private CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository();
        repository.setCookieName(COOKIE_NAME_XSRF_TOKEN);
        repository.setSecure(true);
        repository.setCookiePath("/");
        repository.setCookieMaxAge(securityConfigurationProperties.getCookieMaxAgeSeconds());
        return repository;
    }

    private HeaderWriter relaxedCorsHeaderWriter() {
        return (request, response) -> {
            if (request.getRequestURI().equals(LOGIN_INIT_REQUEST_MAPPING) ||
                    request.getRequestURI().equals(CONSENT_INIT_REQUEST_MAPPING)) {

                String origin = request.getHeader(ORIGIN);
                if (origin != null && !origin.isBlank() && !origin.equals("null")
                        && !response.containsHeader(ACCESS_CONTROL_ALLOW_ORIGIN)) {
                    response.addHeader(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
                    response.addHeader(ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
                }
            }
        };
    }
}
