package com.hooby.token.system.auditor;

import com.hooby.token.domain.user.repository.UserRepository;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import com.hooby.token.domain.user.entity.User;
import com.hooby.token.system.security.model.UserPrincipal;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@RequiredArgsConstructor
public class AuditorAwareImpl implements AuditorAware<User> {
    private final UserRepository userRepository;

    @Override
    @NonNull
    public Optional<User> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return Optional.empty();
        }

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof UserPrincipal userPrincipal)) {
            return Optional.empty();
        }

        Long userId = userPrincipal.getUserId();
        if (userId == null) {
            return Optional.empty();
        }

        return userRepository.findById(userId);
    }
}
