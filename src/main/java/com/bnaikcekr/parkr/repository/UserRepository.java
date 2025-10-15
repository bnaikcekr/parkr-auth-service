package com.bnaikcekr.parkr.repository;

import com.bnaikcekr.parkr.model.ParkerUser;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UserRepository extends CrudRepository<ParkerUser, String> {

    @Query("SELECT e FROM ParkerUser e WHERE e.username = :username")
    Optional<ParkerUser> findByUsername(String username);

}
