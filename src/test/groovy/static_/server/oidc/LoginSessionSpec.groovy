package static_.server.oidc

import io.micronaut.context.annotation.Property
import io.micronaut.http.simple.SimpleHttpRequest
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.cookie.Cookie
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.session.SessionLoginHandler
import io.micronaut.session.Session
import io.micronaut.session.SessionStore
import io.micronaut.session.http.SessionForRequest
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

import java.time.Duration
import java.time.Instant

@MicronautTest
@Property(name = 'micronaut.security.enabled', value = 'true')
@Property(name = 'micronaut.security.oauth2.enabled', value = 'false')
@Property(name = 'micronaut.server.port', value = '-1')
class LoginSessionSpec extends Specification {
    @Inject EmbeddedServer server
    @Inject SessionStore<Session> sessionStore
    @Inject SessionLoginHandler loginHandler

    void 'login returns to the requested path and query, or the fallback for direct login'() {
        given:
        def configuration = new DefaultHttpClientConfiguration()
        configuration.followRedirects = false
        def client = HttpClient.create(server.URL, configuration)

        when:
        def rejected = client.toBlocking().exchange(
            HttpRequest.GET('/docs/guide.html?section=install').accept(MediaType.TEXT_HTML))
        def callback = new SimpleHttpRequest(io.micronaut.http.HttpMethod.GET, '/oauth/callback/default', null)
            .cookie(rejected.getCookie('ORIGINAL_URI').get())
        def response = loginHandler.loginSuccess(Authentication.build('reader'), callback)

        then:
        rejected.status() == HttpStatus.SEE_OTHER
        rejected.header('Location') == '/oauth/login/default'
        response.status() == HttpStatus.SEE_OTHER
        response.header('Location') == '/docs/guide.html?section=install'
        response.getCookie('ORIGINAL_URI').get().maxAge == 0

        when:
        def directLogin = loginHandler.loginSuccess(Authentication.build('reader'),
            new SimpleHttpRequest(io.micronaut.http.HttpMethod.GET, '/oauth/callback/default', null))

        then:
        directLogin.header('Location') == '/'

        cleanup:
        client?.close()
    }

    void 'session lasts an hour of inactivity and authenticated requests renew it'() {
        given:
        def request = new SimpleHttpRequest(io.micronaut.http.HttpMethod.GET, '/oauth/callback/default', null)
        loginHandler.loginSuccess(Authentication.build('reader'), request)
        def session = SessionForRequest.find(request).get()
        sessionStore.save(session).get()
        def configuration = new DefaultHttpClientConfiguration()
        configuration.followRedirects = false
        def client = HttpClient.create(server.URL, configuration)

        expect:
        session.maxInactiveInterval == Duration.ofHours(1)

        when: 'the user has been idle for 59 minutes'
        session.setLastAccessedTime(Instant.now().minus(Duration.ofMinutes(59)))

        then:
        !session.expired

        when: 'a request uses the authenticated session'
        def cookieValue = Base64.encoder.encodeToString(session.id.getBytes('UTF-8'))
        // Use an unknown static path to observe 404 (authenticated) rather than 303 (rejected).
        def response
        try {
            response = client.toBlocking().exchange(HttpRequest.GET('/missing-session-test.html')
                .accept(MediaType.TEXT_HTML).cookie(Cookie.of('SESSION', cookieValue)))
        } catch (io.micronaut.http.client.exceptions.HttpClientResponseException e) {
            response = e.response
        }

        then:
        response.status() == HttpStatus.NOT_FOUND
        session.lastAccessedTime.isAfter(Instant.now().minusSeconds(10))
        !session.expired

        when: 'no further requests arrive for over an hour'
        session.setLastAccessedTime(Instant.now().minus(Duration.ofHours(1)).minusSeconds(1))

        then:
        session.expired

        cleanup:
        client?.close()
        if (session != null) sessionStore.deleteSession(session.id).get()
    }
}
