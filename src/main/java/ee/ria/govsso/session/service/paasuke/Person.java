package ee.ria.govsso.session.service.paasuke;

import lombok.Builder;
import lombok.NonNull;

@Builder
public record Person(
        @NonNull String type,
        String firstName,
        String surname,
        String legalName,
        @NonNull String identifier
) {}
