package ee.ria.govsso.session.service.admin;

import lombok.Builder;
import lombok.NonNull;
import lombok.extern.jackson.Jacksonized;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.time.OffsetDateTime;
import java.util.Map;

@Builder
@Jacksonized
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record ServiceSession(@NonNull Map<String, String> clientNames,
                             @NonNull OffsetDateTime authenticatedAt,
                             @NonNull OffsetDateTime expiresAt,
                             @NonNull OffsetDateTime lastUpdatedAt) {
}
