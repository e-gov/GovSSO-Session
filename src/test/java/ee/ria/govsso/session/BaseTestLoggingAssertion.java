package ee.ria.govsso.session;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static ch.qos.logback.classic.Level.WARN;
import static java.util.List.of;
import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.slf4j.Logger.ROOT_LOGGER_NAME;
import static org.slf4j.LoggerFactory.getLogger;

@Slf4j
public class BaseTestLoggingAssertion {

    private static ListAppender<ILoggingEvent> mockLogAppender;

    @BeforeEach
    public void addMockLogAppender() {
        mockLogAppender = new ListAppender<>();
        ((Logger) getLogger(ROOT_LOGGER_NAME)).addAppender(mockLogAppender);
        mockLogAppender.start();
    }

    @AfterEach
    public void afterEachTest() {
        List<ILoggingEvent> unmatchedErrorsAndWarnings = mockLogAppender.list.stream()
                .filter(e -> e.getLevel() == ERROR || e.getLevel() == WARN)
                .collect(Collectors.toList());
        ((Logger) getLogger(ROOT_LOGGER_NAME)).detachAppender(mockLogAppender);
        assertThat(unmatchedErrorsAndWarnings, empty());
    }

    protected List<ILoggingEvent> assertInfoIsLogged(String... messagesInRelativeOrder) {
        return assertMessageIsLogged(null, INFO, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertWarningIsLogged(String... messagesInRelativeOrder) {
        return assertMessageIsLogged(null, WARN, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertErrorIsLogged(String... messagesInRelativeOrder) {
        return assertMessageIsLogged(null, ERROR, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertInfoIsLogged(Class<?> loggerClass, String... messagesInRelativeOrder) {
        return assertMessageIsLogged(loggerClass, INFO, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertWarningIsLogged(Class<?> loggerClass, String... messagesInRelativeOrder) {
        return assertMessageIsLogged(loggerClass, WARN, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertErrorIsLogged(Class<?> loggerClass, String... messagesInRelativeOrder) {
        return assertMessageIsLogged(loggerClass, ERROR, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertMessageIsLogged(Predicate<ILoggingEvent> additionalFilter, String... messagesInRelativeOrder) {
        return assertMessageIsLogged(null, null, additionalFilter, messagesInRelativeOrder);
    }

    private List<ILoggingEvent> assertMessageIsLogged(Class<?> loggerClass, Level loggingLevel, String... messagesInRelativeOrder) {
        return assertMessageIsLogged(loggerClass, loggingLevel, null, messagesInRelativeOrder);
    }

    @SuppressWarnings("unchecked")
    private List<ILoggingEvent> assertMessageIsLogged(Class<?> loggerClass, Level loggingLevel, Predicate<ILoggingEvent> additionalFilter, String... messagesInRelativeOrder) {
        List<String> expectedMessages = of(messagesInRelativeOrder);
        Stream<ILoggingEvent> eventStream = mockLogAppender.list.stream()
                .filter(e -> loggingLevel == null || e.getLevel() == loggingLevel)
                .filter(e -> loggerClass == null || e.getLoggerName().equals(loggerClass.getCanonicalName()))
                .filter(e -> expectedMessages.stream().anyMatch(expected -> e.getFormattedMessage().startsWith(expected)));
        if (additionalFilter != null) {
            eventStream = eventStream.filter(additionalFilter);
        }
        List<ILoggingEvent> events = eventStream.collect(toList());
        mockLogAppender.list.removeAll(events);
        List<String> messages = events.stream().map(ILoggingEvent::getFormattedMessage).collect(toList());
        assertThat("Expected log messages not found in output.\n\tExpected log messages: " + of(messagesInRelativeOrder) + ",\n\tActual log messages: " + messages,
                messages, containsInRelativeOrder(expectedMessages.stream().map(CoreMatchers::startsWith).toArray(Matcher[]::new)));
        return events;
    }

    protected void assertMessageIsNotLogged(Class<?> loggerClass, String message) {
        String loggedMessage = mockLogAppender.list.stream()
                .filter(e -> (loggerClass == null || e.getLoggerName().equals(loggerClass.getCanonicalName())))
                .map(ILoggingEvent::getFormattedMessage)
                .filter(msg -> msg.equals(message))
                .findFirst()
                .orElse(null);
        assertNull(loggedMessage);
    }

    protected void assertMessageWithMarkerIsLoggedOnce(Class<?> loggerClass, Level loggingLevel, String message, String expectedMarket) {
        List<ILoggingEvent> matchingLoggingEvents = mockLogAppender.list.stream()
                .filter(e -> e.getLevel() == loggingLevel &&
                        (loggerClass == null || e.getLoggerName().equals(loggerClass.getCanonicalName())) &&
                        e.getFormattedMessage().equals(message))
                .filter(e -> e.getMarker().toString().startsWith(expectedMarket))
                .collect(toList());
        mockLogAppender.list.removeAll(matchingLoggingEvents);
        assertNotNull(matchingLoggingEvents);
        assertThat(matchingLoggingEvents, hasSize(1));
    }
}
