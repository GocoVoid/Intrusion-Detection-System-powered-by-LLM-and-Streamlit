package com.utilityService.daoImpl;

import java.util.Optional;

import com.utilityService.model.Account;

public interface AccountDao {

	Optional<Account> getAccount(String accountNumber);

	Optional<Boolean> existsById(String accountNumber);

	Optional<Account> saveAccountDetails(Account account);

}