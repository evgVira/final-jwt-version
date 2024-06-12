package org.mcs.finaljwtversion.token.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@Getter
public class AccessVerifyConfig {

    @Value("${jwt.access-secret}")
    private String accessSecretKey;

    private final JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

    @Bean(name = "accessConfigBean")
    public String cryptSecret() throws JOSEException {
        return new OctetSequenceKeyGenerator(256)
                .keyID(accessSecretKey)
                .algorithm(jwsAlgorithm)
                .generate()
                .toJSONString();
    }
}
