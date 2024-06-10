package org.mcs.finaljwtversion.security;

import lombok.RequiredArgsConstructor;
import org.mcs.finaljwtversion.model.Role;
import org.mcs.finaljwtversion.model.UserEntity;
import org.mcs.finaljwtversion.repository.UserEntityRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserEntityService implements UserDetailsService {

    private final UserEntityRepository userEntityRepository;

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
