package ee.ria.govsso.session.configuration.jackson;

import lombok.experimental.UtilityClass;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.ser.std.StdSerializer;

import java.time.Instant;

@UtilityClass
public class InstantAsTimestamp {

    public static class Serializer extends StdSerializer<Instant> {

        @SuppressWarnings("unused") // Required by Jackson
        public Serializer() {
            super(Instant.class);
        }

        @Override
        public void serialize(Instant value, JsonGenerator gen, SerializationContext ctxt) {
            gen.writeNumber(value.getEpochSecond());
        }
    }

    public static class Deserializer extends StdDeserializer<Instant> {

        @SuppressWarnings("unused") // Required by Jackson
        public Deserializer() {
            super(Instant.class);
        }

        @Override
        public Instant deserialize(JsonParser p, DeserializationContext ctxt) {
            return Instant.ofEpochSecond(p.getLongValue());
        }
    }

}
