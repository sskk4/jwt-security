package com.seba.jwt_security.security.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class PasswordChangeRequest{

    @Schema(description = "Current password", example = "1122")
    String currentPassword;

    @Schema(description = "New password", example = "1122")
    String newPassword;
}
