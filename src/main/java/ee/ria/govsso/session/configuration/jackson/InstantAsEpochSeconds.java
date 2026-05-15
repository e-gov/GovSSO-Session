package ee.ria.govsso.session.configuration.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import lombok.experimental.UtilityClass;

import java.io.IOException;
import java.time.Instant;

@UtilityClass
public class InstantAsEpochSeconds {

    public static class Serializer extends StdSerializer<Instant> {

        @SuppressWarnings("unused") // Required by Jackson
        public Serializer() {
            this(null);
        }

        public Serializer(Class<Instant> t) {
            super(t);
        }

        @Override
        public void serialize(Instant value, JsonGenerator gen, SerializerProvider provider) throws IOException {
            gen.writeNumber(value.getEpochSecond());
        }
    }

    public static class Deserializer extends StdDeserializer<Instant> {

        @SuppressWarnings("unused") // Required by Jackson
        public Deserializer() {
            this(null);
        }

        public Deserializer(Class<Instant> t) {
            super(t);
        }

        @Override
        public Instant deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            return Instant.ofEpochSecond(p.getLongValue());
        }
    }

}
