package ee.ria.govsso.session.logging;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import net.logstash.logback.decorate.JsonFactoryDecorator;

public class LogbackJsonFactoryDecorator implements JsonFactoryDecorator {

    @Override
    public JsonFactory decorate(JsonFactory factory) {
        ObjectMapper objectMapper = (ObjectMapper) factory.getCodec();
        objectMapper
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        return factory;
    }
}
