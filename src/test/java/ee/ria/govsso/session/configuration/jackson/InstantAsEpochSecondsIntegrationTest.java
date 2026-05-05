package ee.ria.govsso.session.configuration.jackson;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;


class InstantAsEpochSecondsIntegrationTest {

    private static final String TIMESTAMP_STRING = "1777028089";
    private static final Instant INSTANT = Instant.ofEpochSecond(Long.parseLong(TIMESTAMP_STRING));

    private final JsonMapper jsonMapper = new JsonMapper();

    @Test
    @SneakyThrows
    void serialize() {
        Data dataObj = new Data(INSTANT);

        String result = jsonMapper.writeValueAsString(dataObj);

        assertThat(result).isEqualTo("{\"instant\":%s}".formatted(TIMESTAMP_STRING));
    }

    @Test
    @SneakyThrows
    void deserialize() {
        String json = "{\"instant\":%s}".formatted(TIMESTAMP_STRING);

        Data result = jsonMapper.readValue(json, Data.class);

        assertThat(result).isEqualTo(new Data(INSTANT));
    }

    record Data(
            @JsonSerialize(using = InstantAsEpochSeconds.Serializer.class)
            @JsonDeserialize(using = InstantAsEpochSeconds.Deserializer.class)
            Instant instant
    ) {}

}
