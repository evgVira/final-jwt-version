package org.mcs.finaljwtversion.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mcs.finaljwtversion.security.config.PasswordEncoderConfig;
import org.mcs.finaljwtversion.token.model.AccessToken;
import org.mcs.finaljwtversion.token.model.RefreshToken;
import org.mcs.finaljwtversion.token.model.TokenRequestDto;
import org.mcs.finaljwtversion.token.model.TokenResponseDto;
import org.mcs.finaljwtversion.token.tokenFactory.AccessTokenFactory;
import org.mcs.finaljwtversion.token.tokenFactory.RefreshTokenFactory;
import org.mcs.finaljwtversion.token.tokenStringSerializer.AccessTokenStringSerializer;
import org.mcs.finaljwtversion.token.tokenStringSerializer.RefreshTokenStringSerializer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.nio.file.AccessDeniedException;

@Service
@RequiredArgsConstructor
@Component
@Slf4j
public class CreateTokenService {

    private final PasswordEncoderConfig passwordEncoderConfig;

    private final AccessTokenFactory accessTokenFactory;

    private final RefreshTokenFactory refreshTokenFactory;

    private final AccessTokenStringSerializer accessTokenStringSerializer;

    private final RefreshTokenStringSerializer refreshTokenStringSerializer;

    private final UserEntityService userEntityService;


    public TokenResponseDto createToken(TokenRequestDto tokenRequestDto) throws AccessDeniedException{

        PasswordEncoder bCryptPasswordEncoder = passwordEncoderConfig.passwordEncoder();

        UserDetails userDetails = userEntityService.loadUserByUsername(tokenRequestDto.getUsername());

        if(tokenRequestDto.getUsername().equals(userDetails.getUsername()) && bCryptPasswordEncoder.matches(tokenRequestDto.getPassword(), userDetails.getPassword())){
            RefreshToken refreshToken = refreshTokenFactory.apply(userDetails);
            AccessToken accessToken = accessTokenFactory.apply(refreshToken);

            String accessTokenToString = accessTokenStringSerializer.apply(accessToken);
            String refreshTokenToString = refreshTokenStringSerializer.apply(refreshToken);

            return TokenResponseDto.builder()
                    .accessToken(accessTokenToString)
                    .refreshToken(refreshTokenToString)
                    .build();
        }else {
            log.error("user not authenticated");
            throw new AccessDeniedException("User must be authenticated");
        }
    }
}
