package org.mcs.finaljwtversion.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.mcs.finaljwtversion.token.model.AccessToken;
import org.mcs.finaljwtversion.token.model.RefreshToken;
import org.mcs.finaljwtversion.token.model.TokenResponseDto;
import org.mcs.finaljwtversion.token.model.TokenUser;
import org.mcs.finaljwtversion.token.tokenFactory.AccessTokenFactory;
import org.mcs.finaljwtversion.token.tokenStringSerializer.AccessTokenStringSerializer;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.file.AccessDeniedException;

@RequiredArgsConstructor
@Component
public class RefreshTokenFilter extends OncePerRequestFilter {

    private final RequestMatcher requestMatcher = new AntPathRequestMatcher("/token/refresh", HttpMethod.POST.name());

    private final AccessTokenFactory accessTokenFactory;

    private final AccessTokenStringSerializer accessTokenStringSerializer;

    private final SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final String CHECK_REFRESH_AUTHORITY = "JWT_REFRESH";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (requestMatcher.matches(request)) {
            if (securityContextRepository.containsContext(request)) {
                var context = securityContextRepository.loadDeferredContext(request).get();
                if (context != null && context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken &&
                        context.getAuthentication().getPrincipal() instanceof TokenUser tokenUser && context.getAuthentication().getAuthorities().contains(new SimpleGrantedAuthority(CHECK_REFRESH_AUTHORITY))) {

                    RefreshToken requestRefreshToken = (RefreshToken) tokenUser.getToken();
                    AccessToken accessToken = accessTokenFactory.apply(requestRefreshToken);

                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                    String accessTokenToString = accessTokenStringSerializer.apply(accessToken);

                    objectMapper.writeValue(response.getWriter(), new TokenResponseDto(accessTokenToString, null));
                    return;
                }
            }
            throw new AccessDeniedException("User must be authenticated");
        }

        filterChain.doFilter(request, response);

    }
}
