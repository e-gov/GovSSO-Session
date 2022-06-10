package ee.ria.govsso.session.actuator.health;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.tara.TaraMetadataService;
import ee.ria.govsso.session.util.ExceptionUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
class TaraHealthIndicator implements HealthIndicator {

    private final TaraMetadataService taraMetadataService;

    @Override
    public Health health() {
        return isTaraUp()
                ? Health.up().build()
                : Health.down().build();
    }

    private boolean isTaraUp() {
        try {
            OIDCProviderMetadata metadata = taraMetadataService.getMetadata();
            return metadata != null;
        } catch (SsoException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to get TARA metadata: {}", ExceptionUtil.getCauseMessages(e), e);
            }
            return false;
        }
    }
}
