package com.seba.jwt_security.security.request;

import com.seba.jwt_security.model.Role;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class SetRoleRequest {
    @NotNull
    private Role role;
}
