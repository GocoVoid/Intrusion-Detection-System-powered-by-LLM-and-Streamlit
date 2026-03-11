package com.utilityService.daoImpl;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.utilityService.model.FixedDeposit;
import com.utilityService.repo.FixedDepositRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class FixedDepositDaoImpl implements FixedDepositDao {
	
	private final FixedDepositRepository fixedDepositRepository;
	
	@Override
	public Optional<FixedDeposit> saveFdDetails(FixedDeposit fixedDeposit) {
		FixedDeposit fd = fixedDepositRepository.save(fixedDeposit);
		return Optional.of(fd);
	}
	
	@Override
	public Optional<List<FixedDeposit>> findFundingAccountNumber(String accountNumber) {
		List<FixedDeposit> fdList = fixedDepositRepository.findByFundingAccountNumber(accountNumber);
		return Optional.of(fdList);
	}

}
