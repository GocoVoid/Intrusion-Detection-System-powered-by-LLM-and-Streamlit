package com.utilityService.daoImpl;

import java.util.List;
import java.util.Optional;

import com.utilityService.model.FixedDeposit;

public interface FixedDepositDao {

	Optional<FixedDeposit> saveFdDetails(FixedDeposit fixedDeposit);

	Optional<List<FixedDeposit>> findFundingAccountNumber(String accountNumber);

}