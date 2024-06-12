package org.mcs.finaljwtversion.token.tokenStringSerializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mcs.finaljwtversion.token.config.RefreshVerifyConfig;
import org.mcs.finaljwtversion.token.model.RefreshToken;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.function.Function;

@Component
@Slf4j
@RequiredArgsConstructor
@Qualifier("refreshConfigBean")
public class RefreshTokenStringSerializer implements Function<RefreshToken, String> {


    private final RefreshVerifyConfig refreshVerifyConfig;

    @Override
    public String apply(RefreshToken refreshToken) {

        JWSHeader jwsHeader = new JWSHeader.Builder(refreshVerifyConfig.getJwsAlgorithm())
                .keyID(refreshToken.getId().toString())
                .build();

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .jwtID(refreshToken.getId().toString())
                .subject(refreshToken.getSubject())
                .claim("authorities", refreshToken.getAuthorities())
                .issueTime(refreshToken.getCreatedAt())
                .expirationTime(refreshToken.getExpiresAt())
                .build();

        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);

        try {
            JWSSigner jwsSigner = new MACSigner(refreshVerifyConfig.cryptSecret());

            signedJWT.sign(jwsSigner);

            String refreshTokenToString = signedJWT.serialize();
            return refreshTokenToString;

        }catch (JOSEException exception){
            log.error(exception.getMessage());
        }
        return null;
    }
}
