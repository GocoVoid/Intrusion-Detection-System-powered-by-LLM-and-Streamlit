package com.utilityService.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.NOT_ACCEPTABLE)
public class InvalidDateRangeException extends RuntimeException {

	public InvalidDateRangeException(String message) {
		super(message);
	} 
	
}
