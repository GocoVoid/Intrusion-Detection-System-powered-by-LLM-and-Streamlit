package com.utilityService.serviceImpl;

import com.utilityService.daoImpl.AccountDao;
import com.utilityService.exception.AccountNotFoundException;
import com.utilityService.exception.InsufficientBalanceException;
import com.utilityService.model.Account;
import com.utilityService.service.AccountValidationService;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AccountValidationServiceImpl implements AccountValidationService {
    
    private final AccountDao accountDao;

    @Override
    public boolean doesAccountExist(String accountNumber) {
    	Optional<Boolean> result = accountDao.existsById(accountNumber);
    	if (result.isPresent()) {
    		return result.get();
    	} else {
    		throw new AccountNotFoundException("A/c no. "+accountNumber+" does not exist");
    	}
    }

    @Override
    public boolean hasSufficientBalance(String accountNumber, BigDecimal amountRequested) {
    	
    	Optional<Account> acc = accountDao.getAccount(accountNumber);
    	if (acc.isPresent()) {
	        return acc.map(account-> account.getAvailableBalance().compareTo(amountRequested) >= 0)
	                .orElse(false);
    	} else {
    		throw new InsufficientBalanceException("Account does not have sufficient balance");
    	}
    }

    @Override
    public BigDecimal getAvailableBalance(String accountNumber) {
    	
    	Optional<Account> acc = accountDao.getAccount(accountNumber);
    	if (acc.isPresent()) {
	        return acc
	                .map(Account::getAvailableBalance)
	                .orElseThrow(() -> new AccountNotFoundException("Account not found: " + accountNumber));
    	}
    	return null;
    }

//    @Override
//    public boolean verifyTransactionPassword(Long customerId, String rawPassword) {
//        return customerRepository.findById(customerId)
//                .map(customer -> customer.getTransactionPassword().equals(rawPassword))
//                .orElse(false);
//    }

	@Override
	public Long getCustomerIdByAccountNumber(String accountNumber) {
		Optional<Account> acc = accountDao.getAccount(accountNumber);
		if (acc.isPresent()) {
			return acc
	                .map(Account::getUserId)
	                .orElseThrow(() -> new AccountNotFoundException("Account not found: " + accountNumber));
		}
		return null;
	}
}

