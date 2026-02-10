package ee.ria.govsso.session.common;

import lombok.Builder;
import lombok.NonNull;

@Builder
public record ClientRequestMetadata(
        @NonNull String ipAddress,
        @NonNull String userAgent,
        String ipCountry
) {}