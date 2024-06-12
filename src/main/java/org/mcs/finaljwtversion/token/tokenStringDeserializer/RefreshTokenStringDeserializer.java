package org.mcs.finaljwtversion.token.tokenStringDeserializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mcs.finaljwtversion.token.config.RefreshVerifyConfig;
import org.mcs.finaljwtversion.token.model.RefreshToken;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

@Component
@RequiredArgsConstructor
@Qualifier("refreshConfigBean")
@Slf4j
public class RefreshTokenStringDeserializer implements Function<String, RefreshToken> {

    private final RefreshVerifyConfig refreshVerifyConfig;

    @Override
    public RefreshToken apply(String s) {
        try {

            MACVerifier macVerifier = new MACVerifier(refreshVerifyConfig.cryptSecret());

            SignedJWT signedJWT = SignedJWT.parse(s);

            if(signedJWT.verify(macVerifier)){

                JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

                return RefreshToken.builder()
                        .id(UUID.fromString(jwtClaimsSet.getJWTID()))
                        .subject(jwtClaimsSet.getSubject())
                        .authorities(jwtClaimsSet.getStringListClaim("authorities"))
                        .createdAt(jwtClaimsSet.getIssueTime())
                        .expiresAt(jwtClaimsSet.getExpirationTime())
                        .build();
            }

        }catch (ParseException | JOSEException exception){
            log.error("can't parse refresh token: %s".formatted(exception.getMessage()));
        }
        return null;
    }
}
