package com.hooby.token.system.security.util;

import com.hooby.token.domain.user.entity.User;
import com.hooby.token.domain.user.repository.UserRepository;
import com.hooby.token.system.security.model.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserLoadService {
    private final UserRepository userRepository;

    public Optional<UserPrincipal> loadUserById(Long userId) {
        return userRepository.findById(userId)
                .map(UserPrincipal::from);
    }

    public Optional<UserPrincipal> loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username);
        return user != null ? Optional.of(UserPrincipal.from(user)) : Optional.empty();
    }
}
