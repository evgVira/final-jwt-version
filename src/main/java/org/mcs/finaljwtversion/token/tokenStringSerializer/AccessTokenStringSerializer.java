package org.mcs.finaljwtversion.token.tokenStringSerializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mcs.finaljwtversion.token.config.AccessVerifyConfig;
import org.mcs.finaljwtversion.token.model.AccessToken;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.function.Function;

@Component
@Slf4j
@RequiredArgsConstructor
@Qualifier("accessConfigBean")
public class AccessTokenStringSerializer implements Function<AccessToken, String> {


    private final AccessVerifyConfig accessVerifyConfig;

    @Override
    public String apply(AccessToken accessToken) {

        JWSHeader jwsHeader = new JWSHeader.Builder(accessVerifyConfig.getJwsAlgorithm())
                .keyID(accessToken.getId().toString())
                .build();

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .jwtID(accessToken.getId().toString())
                .subject(accessToken.getSubject())
                .claim("authorities", accessToken.getAuthorities())
                .issueTime(accessToken.getCreatedAt())
                .expirationTime(accessToken.getExpiresAt())
                .build();

        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);

        try {

            JWSSigner jwsSigner = new MACSigner(accessVerifyConfig.cryptSecret());

            signedJWT.sign(jwsSigner);

            String accessTokenToString = signedJWT.serialize();
            return accessTokenToString;

        }catch (JOSEException exception){
            log.error(exception.getMessage());
        }
        return null;
    }

}
