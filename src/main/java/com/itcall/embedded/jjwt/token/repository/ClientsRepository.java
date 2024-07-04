package com.itcall.embedded.jjwt.token.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;

import com.itcall.embedded.jjwt.token.entity.Clients;

@Repository
public interface ClientsRepository extends CrudRepository<Clients, Long>, PagingAndSortingRepository<Clients, Long> {
	Optional<Clients> findByClientId(String clientId);
}
