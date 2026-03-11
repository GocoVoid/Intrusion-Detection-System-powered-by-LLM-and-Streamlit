package com.utilityService.daoImpl;

import java.util.Optional;

import com.utilityService.model.Transaction;

public interface TransactionDao {

	Optional<Transaction> saveTransaction(Transaction transaction);

}