package club._8b1t.fluxchat.dto.auth;

import lombok.Data;

@Data
public class LoginRequest {
    private String account;
    private String password;
}
