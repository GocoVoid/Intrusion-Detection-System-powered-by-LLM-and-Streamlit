package com.utilityService.repo;

import com.utilityService.model.Transaction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface TransactionRepository extends JpaRepository<Transaction, Long> {

    List<Transaction> findByAccountNumberAndDateBetween(
            String accountNumber, 
            LocalDateTime fromDate, 
            LocalDateTime toDate
    );

    List<Transaction> findTop10ByAccountNumberOrderByDateDesc(String accountNumber);

	List<Transaction> findAllByUserId(Long userId);

	List<Transaction> findAllByAccountNumber(String accountNumber);
}
