package org.mcs.finaljwtversion.security.config;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.mcs.finaljwtversion.security.JwtAuthenticationConverter;
import org.mcs.finaljwtversion.security.RefreshTokenFilter;
import org.mcs.finaljwtversion.security.UserEntityService;
import org.mcs.finaljwtversion.token.tokenFactory.AccessTokenFactory;
import org.mcs.finaljwtversion.token.tokenStringDeserializer.AccessTokenStringDeserializer;
import org.mcs.finaljwtversion.token.tokenStringDeserializer.RefreshTokenStringDeserializer;
import org.mcs.finaljwtversion.token.tokenStringSerializer.AccessTokenStringSerializer;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationConfigurer extends AbstractHttpConfigurer<JwtAuthenticationConfigurer, HttpSecurity> {

    private final AccessTokenStringDeserializer accessTokenStringDeserializer;

    private final RefreshTokenStringDeserializer refreshTokenStringDeserializer;

    private final UserEntityService userEntityService;

    private final AccessTokenFactory accessTokenFactory;

    private final AccessTokenStringSerializer accessTokenStringSerializer;


    @Override
    public void init(HttpSecurity builder) throws Exception {

        var csrfConfigurer = builder.getConfigurer(CsrfConfigurer.class);
        if (csrfConfigurer != null) {
            csrfConfigurer.ignoringRequestMatchers((new AntPathRequestMatcher("/token", HttpMethod.POST.name())));
        }
    }


    @Override
    public void configure(HttpSecurity builder) throws Exception {


        var jwtAuthenticationFilter = new AuthenticationFilter(builder.getSharedObject(AuthenticationManager.class), new JwtAuthenticationConverter(accessTokenStringDeserializer, refreshTokenStringDeserializer));

        jwtAuthenticationFilter.setSuccessHandler(((request, response, authentication) -> {
            CsrfFilter.skipRequest(request);
        }));
        jwtAuthenticationFilter.setFailureHandler(((request, response, exception) -> {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
        }));

        var jwtRefreshFilter = new RefreshTokenFilter(accessTokenFactory, accessTokenStringSerializer);

        var authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(userEntityService);

        builder
                .addFilterBefore(jwtAuthenticationFilter, CsrfFilter.class)
                .addFilterBefore(jwtRefreshFilter, ExceptionTranslationFilter.class)
                .authenticationProvider(authenticationProvider);

    }
}
