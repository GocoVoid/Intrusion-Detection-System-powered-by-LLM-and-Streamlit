package com.utilityService.serviceImpl;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.utilityService.daoImpl.AccountDao;
import com.utilityService.daoImpl.TransactionDao;
import com.utilityService.dto.FundTransferRequest;
import com.utilityService.exception.InvalidBeneficiaryException;
import com.utilityService.model.Account;
import com.utilityService.model.Transaction;
import com.utilityService.service.AccountValidationService;
import com.utilityService.service.FundTransferService;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class FundTransferServiceImpl implements FundTransferService {
    
    private final AccountDao accountDao;
    private final TransactionDao transactionDao;

    @Override
    @Transactional 
    public String transferFunds(FundTransferRequest request) throws Exception {

        String fromAccountNo = request.getFromAccountNumber();
        String toAccountNo = request.getToAccountNumber();
        BigDecimal amount = request.getAmount();

        if (amount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Transfer amount must be greater than zero.");
        }
        if (fromAccountNo.equals(toAccountNo)) {
            throw new IllegalArgumentException("Cannot transfer funds to the same account.");
        }
        
        Account senderAccount = accountDao.getAccount(fromAccountNo).get();
        Account receiverAccount = accountDao.getAccount(toAccountNo).get();
        
        if (!Objects.equals(senderAccount.getUserId(), receiverAccount.getUserId()) 
                && (!("ACTIVE".equals(senderAccount.getAccountStatus())) 
                || !("ACTIVE".equals(receiverAccount.getAccountStatus())))) {
            
            throw new InvalidBeneficiaryException("Unable to send money to A/c no. " + toAccountNo);
        }

        Account sourceAccount = accountDao.getAccount(fromAccountNo)
                .orElseThrow(() -> new IllegalArgumentException("Source account not found."));

//        if (!accountValidationService.verifyTransactionPassword(sourceAccount.getUserId(), request.getTransactionPassword())) {
//            throw new IllegalArgumentException("Invalid transaction password.");
//        }

        if (sourceAccount.getAvailableBalance().compareTo(amount) < 0) {
            throw new IllegalArgumentException("Insufficient funds in the source account.");
        }

        Account destAccount = accountDao.getAccount(toAccountNo)
                .orElseThrow(() -> new IllegalArgumentException("Destination account not found."));

        sourceAccount.setAvailableBalance(sourceAccount.getAvailableBalance().subtract(amount));
        destAccount.setAvailableBalance(destAccount.getAvailableBalance().add(amount));
        
        accountDao.saveAccountDetails(sourceAccount).orElseThrow(() -> new Exception("Unable to update Source Account Details"));
        accountDao.saveAccountDetails(destAccount).orElseThrow(() -> new Exception("Unable to update Destination Account Details"));
        

        String txnRef = "TXN" + System.currentTimeMillis() + UUID.randomUUID().toString().substring(0, 4).toUpperCase();

        Transaction debitTxn = new Transaction();
        debitTxn.setAccountNumber(fromAccountNo);
        debitTxn.setTransactionAmount(amount);
        debitTxn.setType("DR");
        debitTxn.setDate(LocalDateTime.now());
        debitTxn.setDescription("Fund Transfer to " + toAccountNo + " (Ref: " + txnRef + ") - " + request.getRemarks());
        debitTxn.setUserId(accountDao.getAccount(fromAccountNo).get().getUserId());
        transactionDao.saveTransaction(debitTxn).orElseThrow(() -> new Exception("Unable to update Source Account Transactions"));

        Transaction creditTxn = new Transaction();
        creditTxn.setAccountNumber(toAccountNo);
        creditTxn.setTransactionAmount(amount);
        creditTxn.setType("CR");
        creditTxn.setDate(LocalDateTime.now());
        creditTxn.setDescription("Fund Transfer from " + fromAccountNo + " (Ref: " + txnRef + ") - " + request.getRemarks());
        creditTxn.setUserId(accountDao.getAccount(toAccountNo).get().getUserId());
        transactionDao.saveTransaction(creditTxn).orElseThrow(() -> new Exception("Unable to update Destination Account Transactions"));

        return txnRef;
    }

}
