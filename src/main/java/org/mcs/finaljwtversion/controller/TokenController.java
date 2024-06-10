package org.mcs.finaljwtversion.controller;

import lombok.RequiredArgsConstructor;
import org.mcs.finaljwtversion.security.CreateTokenService;
import org.mcs.finaljwtversion.token.model.TokenRequestDto;
import org.mcs.finaljwtversion.token.model.TokenResponseDto;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.AccessDeniedException;

@RestController
@RequiredArgsConstructor
public class TokenController {

    private final CreateTokenService createTokenService;

    @PostMapping("/token")
    public TokenResponseDto createToken(@RequestBody TokenRequestDto tokenRequestDto) throws AccessDeniedException {
        return createTokenService.createToken(tokenRequestDto);
    }
}
