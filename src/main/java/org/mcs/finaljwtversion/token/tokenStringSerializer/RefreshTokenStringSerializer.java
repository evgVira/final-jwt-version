package org.mcs.finaljwtversion.token.tokenStringSerializer;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.mcs.finaljwtversion.token.model.RefreshToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.function.Function;

@Component
@Slf4j
public class RefreshTokenStringSerializer implements Function<RefreshToken, String> {

    @Value("${jwt.refresh-secret}")
    private String refreshTokenSecret;

    private final JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

    @Override
    public String apply(RefreshToken refreshToken) {

        JWSHeader jwsHeader = new JWSHeader.Builder(jwsAlgorithm)
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
            JWSSigner jwsSigner = new MACSigner(cryptRefreshSecret(refreshTokenSecret));

            signedJWT.sign(jwsSigner);

            String refreshTokenToString = signedJWT.serialize();
            return refreshTokenToString;

        }catch (JOSEException exception){
            log.error(exception.getMessage());
        }
        return null;
    }

    private String cryptRefreshSecret(String refreshTokenSecret) throws JOSEException {

        return new OctetSequenceKeyGenerator(256)
                .keyID(refreshTokenSecret)
                .algorithm(jwsAlgorithm)
                .generate()
                .toJSONString();
    }
}
