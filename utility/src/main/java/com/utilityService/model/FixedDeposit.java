package com.utilityService.model;

import jakarta.persistence.*;
import lombok.Data;
import java.math.BigDecimal;
import java.time.LocalDate;

@Entity
@Table(name = "fixed_deposits")
@Data
public class FixedDeposit {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long fdId;

    @Column(nullable = false)
    private BigDecimal depositAmount;

    @Column(nullable = false)
    private String natureOfDeposit; //	MONTHLY, QUARTERLY, ANNUALLY

    @Column(nullable = false)
    private LocalDate creationDate;

    @Column(nullable = false)
    private LocalDate maturityDate;

    @Column(nullable = false)
    private String fundingAccountNumber;
    
}