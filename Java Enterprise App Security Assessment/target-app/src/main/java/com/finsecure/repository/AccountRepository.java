package com.finsecure.repository;

import com.finsecure.model.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AccountRepository extends JpaRepository<Account, Long> {

    // Safe JPQL query — used in some endpoints
    List<Account> findByOwnerEmail(String email);

    // VULN: Native query with string interpolation — used in second-order SQLi endpoint
    @Query(value = "SELECT * FROM accounts WHERE owner_name = ?1", nativeQuery = true)
    List<Account> findByOwnerNameNative(String ownerName);
}
