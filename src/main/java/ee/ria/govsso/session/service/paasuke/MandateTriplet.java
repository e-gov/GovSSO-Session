package ee.ria.govsso.session.service.paasuke;

import lombok.Builder;
import lombok.NonNull;

import java.util.List;

@Builder
public record MandateTriplet(
        @NonNull Person representee,
        @NonNull Person delegate,
        @NonNull List<Mandate> mandates
) {
    @Builder
    public record Mandate(
            @NonNull String role
    ) {}
}
