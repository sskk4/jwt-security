package com.seba.jwt_security.security;

import com.seba.jwt_security.model.User;
import lombok.*;

import java.security.Principal;

@Data
@Getter
@Setter
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class CustomPrincipal implements Principal {
    private String name; // email
    private Long userId;

    @Override
    public String getName() {
        return name;
    }

    public CustomPrincipal(User user) {
        this.userId = user.getId();
        this.name = user.getEmail();
    }
}

