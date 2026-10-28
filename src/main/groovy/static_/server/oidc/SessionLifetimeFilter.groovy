package static_.server.oidc

import groovy.transform.CompileStatic
import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.annotation.Filter
import io.micronaut.http.filter.HttpServerFilter
import io.micronaut.http.filter.ServerFilterChain
import io.micronaut.security.filters.SecurityFilter
import io.micronaut.session.Session
import io.micronaut.session.SessionStore
import io.micronaut.session.http.HttpSessionFilter
import io.micronaut.session.http.HttpSessionIdEncoder
import io.micronaut.session.http.SessionForRequest
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

import java.time.Duration
import java.time.Instant

@CompileStatic
@Filter('/**')
class SessionLifetimeFilter implements HttpServerFilter {
    private static final Duration MAX_LIFETIME = Duration.ofHours(12)
    private final SessionStore<Session> sessionStore
    private final List<HttpSessionIdEncoder> encoders

    SessionLifetimeFilter(SessionStore<Session> sessionStore, List<HttpSessionIdEncoder> encoders) {
        this.sessionStore = sessionStore
        this.encoders = encoders
    }

    @Override
    int getOrder() {
        // Inspect the resolved session before security can authenticate it.
        HttpSessionFilter.ORDER + 1
    }

    @Override
    Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        Session session = SessionForRequest.find(request).orElse(null)
        // Micronaut creates a new session at successful login; activity only changes last access.
        if (session == null || Instant.now().isBefore(session.creationTime.plus(MAX_LIFETIME))) {
            return chain.proceed(request)
        }

        session.remove(SecurityFilter.AUTHENTICATION)
        session.setMaxInactiveInterval(Duration.ZERO)
        request.attributes.remove(HttpSessionFilter.SESSION_ATTRIBUTE)
        // Remove it before continuing, and prevent the outer session filter from saving it again.
        Mono.fromFuture(sessionStore.deleteSession(session.id))
            .flatMapMany { ignored -> Flux.from(chain.proceed(request)) }
            .doOnNext { MutableHttpResponse<?> response ->
                encoders.each { HttpSessionIdEncoder encoder -> encoder.encodeId(request, response, session) }
            }
    }
}
