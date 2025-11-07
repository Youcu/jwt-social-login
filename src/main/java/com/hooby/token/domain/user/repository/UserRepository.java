package com.hooby.token.domain.user.repository;

import com.hooby.token.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.lang.NonNull;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String Email);
    Optional<User> findByNickname(String nickname);
    Optional<User> findByUsername(String username);
    boolean existsByEmail(String email);
    boolean existsByNickname(String nickname);
    boolean existsByUsername(String username);
}
