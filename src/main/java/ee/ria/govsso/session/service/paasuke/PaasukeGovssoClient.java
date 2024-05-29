package ee.ria.govsso.session.service.paasuke;

import lombok.NonNull;

public record PaasukeGovssoClient(
        @NonNull String institution,
        @NonNull String clientId
) {
}
