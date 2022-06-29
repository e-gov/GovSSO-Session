package ee.ria.govsso.session.service.alerts;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import ee.ria.govsso.session.util.LocaleUtil;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Alert {
    private String startTime; //TODO Serialization error with OffSetDateTime type
    private String endTime;
    private LoginAlert loginAlert;
    @JsonIgnore
    private String defaultMessage;
    @JsonIgnore
    private boolean loadedFromConf;

    public void setLoginAlert(LoginAlert loginAlert) {
        this.loginAlert = loginAlert;
        this.defaultMessage = getAlertMessage(LocaleUtil.DEFAULT_LANGUAGE);
    }

    public boolean isActive() {
        return getLoginAlert().isEnabled()
                && OffsetDateTime.parse(getStartTime()).isBefore(OffsetDateTime.now())
                && OffsetDateTime.parse(getEndTime()).isAfter(OffsetDateTime.now());
    }

    public String getAlertMessage(String locale) {
        return loginAlert.getMessageTemplates().stream()
                .filter(m -> m.getLocale().equals(locale))
                .map(MessageTemplate::getMessage)
                .findFirst()
                .orElse(defaultMessage);
    }
}

