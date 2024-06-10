package org.mcs.finaljwtversion.token.tokenFactory;

import lombok.extern.slf4j.Slf4j;
import org.mcs.finaljwtversion.token.model.AccessToken;
import org.mcs.finaljwtversion.token.model.RefreshToken;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

@Slf4j
@Component
public class AccessTokenFactory implements Function<RefreshToken, AccessToken> {

    private Duration tokenTtl = Duration.ofMinutes(5);

    @Override
    public AccessToken apply(RefreshToken refreshToken) {

        List<String> authorities = refreshToken.getAuthorities().stream()
                .filter(authority -> authority.startsWith("GRANT_"))
                .map(authority -> authority.replace("GRANT_", ""))
                .toList();

        Date createdAt = Date.from(Instant.now());
        Date expiresAt = new Date(createdAt.getTime() + tokenTtl.toMillis());

        log.info("Access token was created");

        return AccessToken.builder()
                .id(refreshToken.getId())
                .subject(refreshToken.getSubject())
                .authorities(authorities)
                .createdAt(createdAt)
                .expiresAt(expiresAt)
                .build();
    }
}
