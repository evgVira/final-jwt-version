package org.mcs.finaljwtversion.token.tokenFactory;

import lombok.extern.slf4j.Slf4j;
import org.mcs.finaljwtversion.token.model.RefreshToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

@Slf4j
@Component
public class RefreshTokenFactory implements Function<UserDetails, RefreshToken> {

    private Duration tokenTtl = Duration.ofDays(1);

    @Override
    public RefreshToken apply(UserDetails userDetails) {

        List<String> authorities = new ArrayList<>();

        authorities.add("JWT_REFRESH");
        authorities.add("JWT_LOGOUT");

        userDetails.getAuthorities().stream()
                .map("GRANT_%s"::formatted)
                .forEach(authorities::add);

        Date createAt = Date.from(Instant.now());
        Date expiresAt = new Date(createAt.getTime() + tokenTtl.toMillis());

        log.info("Refresh token was created");

        return RefreshToken.builder()
                .id(UUID.randomUUID())
                .subject(userDetails.getUsername())
                .authorities(authorities)
                .createdAt(createAt)
                .expiresAt(expiresAt)
                .build();

    }
}
