package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.configuration.properties.SecurityConfigurationProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

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
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity, HandlerMappingIntrospector introspector) throws Exception {

        httpSecurity
                .securityContext(AbstractHttpConfigurer::disable)
                .anonymous(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .rememberMe(AbstractHttpConfigurer::disable)
                .servletApi(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .csrf((csrf) -> csrf
                        .ignoringRequestMatchers(
                                new MvcRequestMatcher(introspector, TOKEN_REFRESH_REQUEST_MAPPING),
                                new MvcRequestMatcher(introspector, ADMIN_SESSIONS_REQUEST_MAPPING),
                                new MvcRequestMatcher(introspector, ADMIN_SESSIONS_BY_ID_REQUEST_MAPPING))
                        .csrfTokenRepository(csrfTokenRepository())
                        .csrfTokenRequestHandler(csrfRequestHandler()))
                .headers(headersConfigurer -> headersConfigurer
                        .addHeaderWriter(relaxedCorsHeaderWriter())
                        .xssProtection(xssConfig -> xssConfig
                                .headerValue(XXssProtectionHeaderWriter.HeaderValue.DISABLED))
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                        .contentSecurityPolicy(policyConfig -> policyConfig
                                .policyDirectives(securityConfigurationProperties.getContentSecurityPolicy()))
                        .httpStrictTransportSecurity(hstsConfig -> hstsConfig
                                .includeSubDomains(true)
                                .maxAgeInSeconds(Duration.of(186, ChronoUnit.DAYS).toSeconds())));

        return httpSecurity.build();
    }

    private CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository();
        repository.setCookieName(COOKIE_NAME_XSRF_TOKEN);
        repository.setCookieCustomizer(cookieBuilder -> cookieBuilder
                .secure(true)
                .maxAge(securityConfigurationProperties.getCookieMaxAgeSeconds()));
        repository.setCookiePath("/");
        return repository;
    }

    private CsrfTokenRequestHandler csrfRequestHandler() {
        // Use XorCsrfTokenRequestAttributeHandler for BREACH protection (default in Spring Security 6)
        XorCsrfTokenRequestAttributeHandler requestHandler = new XorCsrfTokenRequestAttributeHandler();
        /* Opt-out of Deferred CSRF Tokens as described in
         * https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#deferred-csrf-token.
         * Using deferred CSRF token would sometimes cause setting the CSRF token cookie to be skipped, as by the time
         * setting the CSRF token cookie was triggered, the HttpServletResponse was already committed and thus setting
         * the `Set-Cookie` header would be impossible. */
        requestHandler.setCsrfRequestAttributeName(null);
        return requestHandler;
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
