package static_.server.oidc

import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.annotation.Filter
import io.micronaut.http.exceptions.HttpStatusException
import io.micronaut.http.filter.HttpServerFilter
import io.micronaut.http.filter.ServerFilterChain
import io.micronaut.http.filter.ServerFilterPhase
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.filters.SecurityFilter
import io.micronaut.session.http.SessionForRequest
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux

@CompileStatic
@Slf4j
@Filter('/**')
class RequestAuditFilter implements HttpServerFilter {
    @Override
    int getOrder() {
        // Wrap security and session filters so rejected requests are logged too.
        ServerFilterPhase.FIRST.order()
    }

    @Override
    Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        Flux.defer { -> Flux.from(chain.proceed(request)) }
            .doOnNext { MutableHttpResponse<?> response -> record(request, response.status.code) }
            .doOnError { Throwable failure ->
                record(request, failure instanceof HttpStatusException ? failure.status.code : 500)
            }
    }

    private static void record(HttpRequest<?> request, int status) {
        // These objects are populated by Micronaut after authentication, not by headers.
        Authentication authentication = request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication).orElse(null)
        if (authentication == null) {
            authentication = SessionForRequest.find(request)
                .flatMap { session -> session.get(SecurityFilter.AUTHENTICATION, Authentication) }.orElse(null)
        }
        String principal = authentication == null ? 'anonymous' : authentication.name
        Object emailClaim = authentication?.attributes?.get('email')
        // Log the provider's email claim separately; it need not declare email_verified.
        String email = emailClaim instanceof String && !emailClaim.isBlank() ? (String) emailClaim : '-'
        log.info('request principal="{}" email="{}" method="{}" path="{}" status={}',
            field(principal), field(email), field(request.methodName), field(request.path), status)
    }

    private static String field(String value) {
        // Escape delimiters and control characters to prevent forged log entries.
        value.replace('\\', '\\\\').replace('"', '\\"').replaceAll('[\\p{Cntrl}\\p{Zl}\\p{Zp}]', '?')
    }
}
