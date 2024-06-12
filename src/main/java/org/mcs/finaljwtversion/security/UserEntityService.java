package org.mcs.finaljwtversion.security;

import lombok.RequiredArgsConstructor;
import org.mcs.finaljwtversion.model.Role;
import org.mcs.finaljwtversion.model.UserEntity;
import org.mcs.finaljwtversion.repository.UserEntityRepository;
import org.mcs.finaljwtversion.token.model.AccessToken;
import org.mcs.finaljwtversion.token.model.RefreshToken;
import org.mcs.finaljwtversion.token.model.TokenUser;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class UserEntityService implements UserDetailsService, AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private final UserEntityRepository userEntityRepository;

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken authenticationToken) throws UsernameNotFoundException {
        if(authenticationToken.getPrincipal() instanceof AccessToken accessToken){

            return new TokenUser(accessToken.getSubject(), "noopassword", true, true, accessToken.getExpiresAt().toInstant().isAfter(Instant.now()), true, accessToken.getAuthorities().stream()
                    .map(SimpleGrantedAuthority::new)
                    .toList(), accessToken);

        }else if(authenticationToken.getPrincipal() instanceof RefreshToken refreshToken){

            return new TokenUser(refreshToken.getSubject(), "noopassword", true, true, refreshToken.getExpiresAt().toInstant().isAfter(Instant.now()), true, refreshToken.getAuthorities().stream()
                    .map(SimpleGrantedAuthority::new)
                    .toList(), refreshToken);
        }
        throw new UsernameNotFoundException("user not found");
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity user = getUser(username);

        return new User(user.getName(), user.getPassword(),
                user.getRoles().stream()
                        .map(Role::getName)
                        .map(SimpleGrantedAuthority::new)
                        .toList());
    }

    private UserEntity getUser(String username) {
        return userEntityRepository.findUserEntityByName(username);
    }
}
