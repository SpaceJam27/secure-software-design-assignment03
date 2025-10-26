package edu.nu.owaspapivulnlab.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
// import org.springframework.web.servlet.NoHandlerFoundException; // REMOVED

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@ControllerAdvice
public class GlobalErrorHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalErrorHandler.class);

    private ResponseEntity<Map<String, String>> createErrorResponse(HttpStatus status, String message) {
        return ResponseEntity.status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Collections.singletonMap("error", message));
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<?> handleRuntimeException(RuntimeException e, WebRequest request) {
        logger.error("Runtime Exception: {} - Path: {}", e.getMessage(), request.getDescription(false), e);
        if (e.getMessage() != null && e.getMessage().toLowerCase().contains("not found")) {
            return createErrorResponse(HttpStatus.NOT_FOUND, "Resource not found");
        }
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred. Please try again later.");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> handleValidationExceptions(MethodArgumentNotValidException e, WebRequest request) {
        Map<String, String> errors = new HashMap<>();
        e.getBindingResult().getFieldErrors().forEach(error ->
                errors.put(error.getField(), error.getDefaultMessage()));
        logger.warn("Validation Error: {} - Path: {}", errors, request.getDescription(false));
        String errorMessage = "Validation failed: " + errors.values().stream().collect(Collectors.joining(", "));
        return createErrorResponse(HttpStatus.BAD_REQUEST, errorMessage);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<?> handleDataAccessException(DataAccessException e, WebRequest request) {
        logger.error("Database Access Error: {} - Path: {}", e.getMessage(), request.getDescription(false), e);
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "A database error occurred. Please try again later.");
    }

    // REMOVED: NoHandlerFoundException is often better handled by Spring Security's AuthenticationEntryPoint
    // or through custom configurations if Spring MVC's default error page is undesirable.
    /*
    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<?> handleNoHandlerFoundException(NoHandlerFoundException e, WebRequest request) {
        logger.warn("No Handler Found: {} {} - Path: {}", e.getHttpMethod(), e.getRequestURL(), request.getDescription(false));
        return createErrorResponse(HttpStatus.NOT_FOUND, "Resource not found");
    }
    */

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleAllOtherExceptions(Exception e, WebRequest request) {
        logger.error("An unexpected error occurred: {} - Path: {}", e.getMessage(), request.getDescription(false), e);
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred. Please try again later.");
    }
}
