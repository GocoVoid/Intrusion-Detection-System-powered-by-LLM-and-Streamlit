package com.utilityService.daoImpl;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.utilityService.model.Account;
import com.utilityService.repo.AccountRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AccountDaoImpl implements AccountDao {
	
	private final AccountRepository accountRepository;
	
	@Override
	public Optional<Account> getAccount(String accountNumber) {
		return accountRepository.findById(accountNumber);
	}
	
	@Override
	public Optional<Boolean> existsById(String accountNumber) {
		Boolean result = accountRepository.existsById(accountNumber);
		return Optional.of(result);
	}
	
	@Override
	public Optional<Account> saveAccountDetails(Account account) {
		Account savedAccount = accountRepository.save(account);
		return Optional.of(savedAccount);
	}

}
