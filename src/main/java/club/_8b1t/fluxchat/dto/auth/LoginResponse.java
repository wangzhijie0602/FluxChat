package club._8b1t.fluxchat.dto.auth;

import cn.dev33.satoken.stp.SaTokenInfo;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginResponse {
    private SaTokenInfo tokenInfo;
    private UserProfile user;
}
