package org.mcs.finaljwtversion.token.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class TokenResponseDto {

    private String accessToken;

    private String refreshToken;
}
