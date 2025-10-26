package edu.nu.owaspapivulnlab.DTO;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TransferRequestDTO {
    @NotNull(message = "Transfer amount is required")
    @DecimalMin(value = "0.01", message = "Transfer amount must be positive")
    // You can also add @DecimalMax if there's an upper limit for transfers
    // @DecimalMax(value = "10000.00", message = "Transfer amount cannot exceed 10,000")
    private Double amount;
}
