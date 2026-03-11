package com.utilityService.serviceImpl;

import com.utilityService.daoImpl.AccountDao;
import com.utilityService.daoImpl.FixedDepositDao;
import com.utilityService.daoImpl.TransactionDao;
import com.utilityService.dto.FixedDepositRequest;
import com.utilityService.exception.AccountNotFoundException;
import com.utilityService.exception.InsufficientBalanceException;
import com.utilityService.model.Account;
import com.utilityService.model.FixedDeposit;
import com.utilityService.model.Transaction;
import com.utilityService.service.AccountValidationService;
import com.utilityService.service.FixedDepositService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class FixedDepositServiceImpl implements FixedDepositService {

    private final AccountValidationService accountValidationService;
    
    private final FixedDepositDao fixedDepositDao;
    private final AccountDao accountDao;
    private final TransactionDao transactionDao;

    @Override
    @Transactional
    public FixedDeposit openFixedDeposit(FixedDepositRequest request) throws Exception {
        
        String fundingAccountNo = request.getFundingAccountNumber();
        BigDecimal depositAmount = request.getDepositAmount();

        if (depositAmount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Deposit amount must be greater than zero.");
        }

        if (!accountValidationService.doesAccountExist(fundingAccountNo)) {
            throw new AccountNotFoundException("Funding account does not exist.");
        }
        if (!accountValidationService.hasSufficientBalance(fundingAccountNo, depositAmount)) {
            throw new InsufficientBalanceException("Insufficient funds in the account to open this FD.");
        }

        Optional<Account> acc = accountDao.getAccount(fundingAccountNo);
        
        Account account = null;
        if (acc.isPresent()) {
        	account = acc.get();
        } else {
        	throw new AccountNotFoundException("A/c no. "+fundingAccountNo+" is not available");
        }
        
        account.setAvailableBalance(account.getAvailableBalance().subtract(depositAmount));
        
        Optional<Account> savedAccount = accountDao.saveAccountDetails(account);
        if (!savedAccount.isPresent()) {
        	throw new Exception("Unable to save account details. Try Again.");
        }
        
        LocalDate creationDate = LocalDate.now();
        LocalDate maturityDate = calculateMaturityDate(creationDate, request.getDurationInMonths());
        
        FixedDeposit fd = new FixedDeposit();
        fd.setFundingAccountNumber(fundingAccountNo);
        fd.setDepositAmount(depositAmount);
        fd.setCreationDate(creationDate);
        fd.setMaturityDate(maturityDate);
        fd.setNatureOfDeposit(request.getNatureOfDeposit()); // e.g., "MONTHLY", "QUARTERLY", "REINVESTMENT"
        
        BigDecimal estimatedMaturity = calculateEstimatedMaturityAmount(depositAmount, request.getInterestRate(), request.getNatureOfDeposit(), request.getDurationInMonths());
        
        Optional<FixedDeposit> getSavedFd = fixedDepositDao.saveFdDetails(fd);
        
        FixedDeposit savedFd = null;
        if (getSavedFd.isPresent()) {
        	savedFd = getSavedFd.get();
        } else {
        	throw new Exception("Unable to save FD Details of A/c no. "+fundingAccountNo);
        }
        
        String txnRef = "FD" + System.currentTimeMillis() + UUID.randomUUID().toString().substring(0, 4).toUpperCase();
        
        Transaction debitTxn = new Transaction();
        debitTxn.setAccountNumber(fundingAccountNo);
        debitTxn.setTransactionAmount(depositAmount);
        debitTxn.setType("DR");
        debitTxn.setDate(LocalDateTime.now());
        debitTxn.setDescription("Fixed Deposit Creation (Ref: " + txnRef + ") with expected maturity amount of Rs. "+estimatedMaturity);
        debitTxn.setUserId(accountDao.getAccount(fundingAccountNo).get().getUserId());
        
        //transactionRepository.save(debitTxn);
        Optional<Transaction> savedTransaction = transactionDao.saveTransaction(debitTxn);
        if (!savedTransaction.isPresent()) {
        	throw new Exception("Unable to save debited transaction.");
        }
        
        return savedFd;
    }

    @Override
    public LocalDate calculateMaturityDate(LocalDate creationDate, int durationInMonths) {
        return creationDate.plusMonths(durationInMonths);
    }

    @Override
    public BigDecimal calculateEstimatedMaturityAmount(BigDecimal principal, BigDecimal interestRate, String nature, int durationInMonths) {
        
        if (nature == null) {
            throw new IllegalArgumentException("Nature of deposit cannot be null");
        }

        BigDecimal annualRateDecimal = interestRate.divide(BigDecimal.valueOf(100), 4, RoundingMode.HALF_UP);
        
        BigDecimal timeInYears = BigDecimal.valueOf(durationInMonths).divide(BigDecimal.valueOf(12), 4, RoundingMode.HALF_UP);

        switch (nature.toUpperCase()) {
            
            case "REINVESTMENT":
                int n = 4; 
                BigDecimal rOverN = annualRateDecimal.divide(BigDecimal.valueOf(n), 6, RoundingMode.HALF_UP);
                BigDecimal base = BigDecimal.ONE.add(rOverN);
                
                double exponent = n * timeInYears.doubleValue();
                BigDecimal compoundMultiplier = BigDecimal.valueOf(Math.pow(base.doubleValue(), exponent));
                
                return principal.multiply(compoundMultiplier).setScale(2, RoundingMode.HALF_UP);

            case "MONTHLY":
            case "QUARTERLY":
                BigDecimal totalInterest = principal.multiply(annualRateDecimal).multiply(timeInYears);
                return principal.add(totalInterest).setScale(2, RoundingMode.HALF_UP);

            default:
                throw new IllegalArgumentException("Invalid FD nature. Must be MONTHLY, QUARTERLY, or REINVESTMENT.");
        }
    }

	@Override
	public List<FixedDeposit> getFixedDepositsByAccountNumber(String accountNumber) throws Exception {
        if (!accountValidationService.doesAccountExist(accountNumber)) {
            throw new IllegalArgumentException("Account does not exist: " + accountNumber);
        }
        
        Optional<List<FixedDeposit>> fdList = fixedDepositDao.findFundingAccountNumber(accountNumber);
        if (fdList.isPresent()) {
        	return fdList.get();
        } else {
        	throw new Exception("No FDs linked with A/c no. "+accountNumber);
        }
      
	}

}