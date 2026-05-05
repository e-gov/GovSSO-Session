package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.time.OffsetDateTime;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Consent {

    public static final int REMEMBER_FOR_FOREVER = 0;

    private Integer rememberFor;
    private ConsentRequestInfo consentRequest;

    @JsonIgnore
    @SuppressWarnings("RedundantIfStatement") // If statements are more readable
    public boolean isValidAt(OffsetDateTime time) {
        if (time.isBefore(this.getRequestedAt())) {
            return false;
        }
        OffsetDateTime expiresAt = this.getExpiresAt();
        if (expiresAt != null && time.isAfter(expiresAt)) {
            return false;
        }
        return true;
    }

    @JsonIgnore
    public OffsetDateTime getRequestedAt() {
        return consentRequest.getRequestedAt();
    }

    @JsonIgnore
    public OffsetDateTime getExpiresAt() {
        if (rememberFor == REMEMBER_FOR_FOREVER) {
            return null;
        }
        return getRequestedAt().plusSeconds(rememberFor);
    }
}
