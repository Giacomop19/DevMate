package com.onelife.devmate.repository;

import com.onelife.devmate.model.Person;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PersonRepository extends JpaRepository<Person, Long> {
    Optional<Person> findByUsername(String username);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
}