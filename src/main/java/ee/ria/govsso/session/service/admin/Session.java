package ee.ria.govsso.session.service.admin;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;

import java.time.OffsetDateTime;
import java.util.List;

@Builder
@Jacksonized
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record Session(@NonNull String sessionId,
                      @NonNull OffsetDateTime authenticatedAt,

                      @NonNull List<String> ipAddresses,
                      @NonNull String userAgent,
                      @NonNull List<ServiceSession> services) {
}
