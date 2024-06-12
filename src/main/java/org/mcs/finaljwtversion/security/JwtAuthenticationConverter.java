package org.mcs.finaljwtversion.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mcs.finaljwtversion.token.model.AccessToken;
import org.mcs.finaljwtversion.token.model.RefreshToken;
import org.mcs.finaljwtversion.token.tokenStringDeserializer.AccessTokenStringDeserializer;
import org.mcs.finaljwtversion.token.tokenStringDeserializer.RefreshTokenStringDeserializer;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationConverter implements AuthenticationConverter {

    private final AccessTokenStringDeserializer accessTokenStringDeserializer;

    private final RefreshTokenStringDeserializer refreshTokenStringDeserializer;

    @Override
    public Authentication convert(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {

            String requestToken = header.replace("Bearer ", "");

            AccessToken accessToken = accessTokenStringDeserializer.apply(requestToken);

            if (accessToken != null) {
                return new PreAuthenticatedAuthenticationToken(accessToken, requestToken);
            }

            RefreshToken refreshToken = refreshTokenStringDeserializer.apply(requestToken);

            if (refreshToken != null) {
                return new PreAuthenticatedAuthenticationToken(refreshToken, requestToken);
            }
        }
        log.error("user must be authenticated");
        return null;
    }
}
