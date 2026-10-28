package static_.server.oidc

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.core.read.ListAppender
import io.micronaut.context.annotation.Property
import io.micronaut.http.*
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.HttpClient
import io.micronaut.http.cookie.Cookie
import io.micronaut.http.exceptions.HttpStatusException
import io.micronaut.http.filter.ServerFilterChain
import io.micronaut.http.simple.SimpleHttpRequest
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.filters.SecurityFilter
import io.micronaut.security.session.SessionLoginHandler
import io.micronaut.session.InMemorySession
import io.micronaut.session.Session
import io.micronaut.session.SessionStore
import io.micronaut.session.http.SessionForRequest
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import io.micronaut.test.support.TestPropertyProvider
import jakarta.inject.Inject
import org.slf4j.LoggerFactory
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import java.time.Duration
import java.time.Instant

@MicronautTest
@Property(name = 'micronaut.security.enabled', value = 'true')
@Property(name = 'micronaut.security.oauth2.enabled', value = 'false')
@Property(name = 'micronaut.server.port', value = '-1')
class SecurityAuditSpec extends Specification implements TestPropertyProvider {
    @Shared File documentRoot = File.createTempDir('security-audit-', '')
    @Inject EmbeddedServer server
    @Inject SessionStore<Session> sessionStore
    @Inject SessionLoginHandler loginHandler
    HttpClient client
    Logger auditLogger
    ListAppender appender

    @Override
    Map<String, String> getProperties() {
        new File(documentRoot, 'index.html').text = 'protected content'
        ['PUBLIC_HTML_ROOT': documentRoot.absolutePath]
    }

    void setup() {
        def configuration = new DefaultHttpClientConfiguration()
        configuration.followRedirects = false
        client = HttpClient.create(server.URL, configuration)
        auditLogger = (Logger) LoggerFactory.getLogger(RequestAuditFilter)
        appender = new ListAppender()
        appender.start()
        auditLogger.addAppender(appender)
    }

    void cleanup() {
        auditLogger.detachAppender(appender)
        appender.stop()
        client.close()
    }

    void cleanupSpec() {
        documentRoot.deleteDir()
    }

    @Unroll
    void 'audit uses trusted identity and excludes secrets: #scenario'() {
        given:
        Session session
        def request = HttpRequest.create(method, '/index.html?access_token=DO_NOT_LOG')
            .accept(MediaType.TEXT_HTML).header('X-Forwarded-Email', 'spoofed@example.org')
        if (subject != null) {
            def callback = new SimpleHttpRequest(HttpMethod.GET, '/oauth/callback/default', null)
            loginHandler.loginSuccess(Authentication.build(subject, [], claims), callback)
            session = SessionForRequest.find(callback).get()
            sessionStore.save(session).get()
            request.cookie(sessionCookie(session))
        }

        when:
        def response = client.toBlocking().exchange(request, String)

        then:
        response.status() == (subject == null ? HttpStatus.SEE_OTHER : HttpStatus.OK)
        appender.list.size() == 1
        appender.list[0].level == Level.INFO
        def message = appender.list[0].formattedMessage
        message.contains('user="' + expectedIdentity + '"')
        message.contains('method="' + method + '" path="/index.html" status=' + response.code())
        !message.contains('DO_NOT_LOG')
        !message.contains('access_token')
        !message.contains('spoofed@example.org')
        !message.contains('unverified@example.org')
        !message.contains('\n')
        session == null || (!message.contains(session.id) && !message.contains(sessionCookie(session).value))

        cleanup:
        if (session != null) sessionStore.deleteSession(session.id).get()

        where:
        scenario          | method             | subject          | claims                                                           | expectedIdentity
        'verified email'  | HttpMethod.GET     | 'subject-123'    | [email: 'reader@example.org', email_verified: true]                | 'reader@example.org'
        'unverified email'| HttpMethod.GET     | 'subject-123'    | [email: 'unverified@example.org', email_verified: false]           | 'subject-123'
        'non-boolean verification' | HttpMethod.GET | 'subject-123' | [email: 'unverified@example.org', email_verified: 'true']        | 'subject-123'
        'missing email'   | HttpMethod.GET     | 'subject-123'    | [:]                                                              | 'subject-123'
        'log injection'   | HttpMethod.GET     | 'reader\nforged' | [:]                                                              | 'reader?forged'
        'anonymous GET'   | HttpMethod.GET     | null             | [:]                                                              | 'anonymous'
        'anonymous HEAD'  | HttpMethod.HEAD    | null             | [:]                                                              | 'anonymous'
        'anonymous POST'  | HttpMethod.POST    | null             | [:]                                                              | 'anonymous'
        'anonymous OPTIONS'| HttpMethod.OPTIONS| null             | [:]                                                              | 'anonymous'
    }

    void 'successful login is audited using the newly authenticated session'() {
        given:
        def callback = new SimpleHttpRequest(HttpMethod.GET, '/oauth/callback/default?code=DO_NOT_LOG', null)
        def authentication = Authentication.build('subject-123', [],
            [email: 'reader@example.org', email_verified: true])
        def chain = Stub(ServerFilterChain) {
            proceed(_) >> { HttpRequest request -> Flux.just(loginHandler.loginSuccess(authentication, request)) }
        }
        def filter = server.applicationContext.getBean(RequestAuditFilter)

        when:
        Mono.from(filter.doFilter(callback, chain)).block()

        then:
        appender.list.size() == 1
        appender.list[0].formattedMessage.contains('user="reader@example.org" subject="subject-123"')
        appender.list[0].formattedMessage.contains('path="/oauth/callback/default" status=303')
        !appender.list[0].formattedMessage.contains('DO_NOT_LOG')
    }

    @Unroll
    void 'active session aged #age is accepted only before twelve hours'() {
        given:
        def session = new AgedSession(Instant.now().minus(age))
        session.put(SecurityFilter.AUTHENTICATION, Authentication.build('reader'))
        sessionStore.save(session).get()
        // Recent activity keeps the idle timeout valid, regardless of session age.
        session.setLastAccessedTime(Instant.now())

        when:
        def response = client.toBlocking().exchange(HttpRequest.GET('/index.html')
            .accept(MediaType.TEXT_HTML).cookie(sessionCookie(session)), String)

        then:
        response.status() == expectedStatus
        if (expectedStatus == HttpStatus.SEE_OTHER) {
            assert response.header('Location') == '/oauth/login/default'
            assert response.getCookie('SESSION').get().maxAge == 0
            assert sessionStore.findSession(session.id).get().empty
        } else {
            assert response.body() == 'protected content'
            assert sessionStore.findSession(session.id).get().present
        }

        cleanup:
        sessionStore.deleteSession(session.id).get()

        where:
        age                                 | expectedStatus
        Duration.ofHours(11).plusMinutes(59) | HttpStatus.OK
        Duration.ofHours(12)                 | HttpStatus.SEE_OTHER
        Duration.ofHours(13)                 | HttpStatus.SEE_OTHER
    }

    void 'request errors are audited without exception details'() {
        given:
        def chain = Stub(ServerFilterChain) {
            proceed(_) >> Flux.error(new HttpStatusException(HttpStatus.BAD_REQUEST, 'secret details'))
        }
        def filter = server.applicationContext.getBean(RequestAuditFilter)

        when:
        Mono.from(filter.doFilter(HttpRequest.GET('/error'), chain)).block()

        then:
        thrown(HttpStatusException)
        appender.list.size() == 1
        appender.list[0].formattedMessage.contains('path="/error" status=400')
        !appender.list[0].formattedMessage.contains('secret details')
    }

    private static Cookie sessionCookie(Session session) {
        Cookie.of('SESSION', Base64.encoder.encodeToString(session.id.getBytes('UTF-8')))
    }

    private static class AgedSession extends InMemorySession {
        AgedSession(Instant created) {
            super(UUID.randomUUID().toString(), created, Duration.ofHours(1))
        }
    }
}
