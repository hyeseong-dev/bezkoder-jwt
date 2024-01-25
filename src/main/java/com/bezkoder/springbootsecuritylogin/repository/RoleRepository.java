package com.bezkoder.springbootsecuritylogin.repository;

import com.bezkoder.springbootsecuritylogin.model.ERole;
import com.bezkoder.springbootsecuritylogin.model.Role;
import com.bezkoder.springbootsecuritylogin.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
