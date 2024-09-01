package org.example.userservice.repository;

import org.example.userservice.models.Session;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<Session, Long> {
    @Override
    Session save(Session session);
}
