package com.itcall.embedded.jjwt.token.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.itcall.embedded.jjwt.token.entity.UsersEntity;

@Repository
public interface UsersRepository extends JpaRepository<UsersEntity, Long> {
	Optional<UsersEntity> findById(Long id);
	// UsersEntity findByUsername(String id);
	Optional<UsersEntity> findByUsername(String username);
}