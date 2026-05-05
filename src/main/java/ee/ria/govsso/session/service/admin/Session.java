package ee.ria.govsso.session.service.admin;

import lombok.Builder;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.time.OffsetDateTime;
import java.util.List;

@Builder
@Jacksonized
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record Session(@NonNull String sessionId,
                      @NonNull OffsetDateTime authenticatedAt,

                      @NonNull List<SessionIpInfo> ipInfos,
                      @NonNull String userAgent,
                      @NonNull String os,
                      @NonNull String browser,
                      @NonNull List<ServiceSession> services) {
}
