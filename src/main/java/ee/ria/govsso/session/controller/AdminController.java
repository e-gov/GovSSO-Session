package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.service.admin.AdminService;
import ee.ria.govsso.session.service.admin.Session;
import ee.ria.govsso.session.service.hydra.HydraService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@Validated
@RestController
@RequiredArgsConstructor
public class AdminController {
    public static final String ADMIN_SESSIONS_REQUEST_MAPPING = "/admin/sessions/{subject}";
    public static final String ADMIN_SESSIONS_BY_ID_REQUEST_MAPPING = "/admin/sessions/{subject}/{loginSessionId}";
    private final AdminService adminService;
    private final HydraService hydraService;

    @GetMapping(path = ADMIN_SESSIONS_REQUEST_MAPPING, produces = APPLICATION_JSON_VALUE)
    public List<Session> getBySubject(@PathVariable @NotBlank @Size(min = 1, max = 255) String subject) {
        return adminService.getSessions(subject);
    }

    @DeleteMapping(path = ADMIN_SESSIONS_REQUEST_MAPPING, produces = APPLICATION_JSON_VALUE)
    public void deleteBySubject(@PathVariable @NotBlank @Size(min = 1, max = 255) String subject) {
        hydraService.deleteConsentBySubject(subject);
    }

    @DeleteMapping(path = ADMIN_SESSIONS_BY_ID_REQUEST_MAPPING, produces = APPLICATION_JSON_VALUE)
    public void deleteBySubjectSession(@PathVariable @NotBlank @Size(min = 1, max = 255) String subject,
                                       @PathVariable @Pattern(regexp = "^[0-9a-f-]{36}$") String loginSessionId) {
        hydraService.deleteConsentBySubjectSession(subject, loginSessionId);
    }
}
