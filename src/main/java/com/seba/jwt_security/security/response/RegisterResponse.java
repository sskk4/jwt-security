package com.seba.jwt_security.security.response;

import com.seba.jwt_security.model.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterResponse {

        private String firstname;
        private String lastname;
        private String email;
        private boolean isActive;
        private Role role;
}
