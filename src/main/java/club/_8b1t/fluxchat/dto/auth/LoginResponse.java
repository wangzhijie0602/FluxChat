package club._8b1t.fluxchat.dto.auth;

import cn.dev33.satoken.stp.SaTokenInfo;
import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * 登录响应数据
 * 包含 Token 信息与当前登录用户资料。
 *
 * @module Authentication
 */
@Data
@AllArgsConstructor
public class LoginResponse {
    /**
     * 登录态信息
     * 由 Sa-Token 生成，详见{@link SaTokenInfo}。
     */
    private SaTokenInfo tokenInfo;

    /**
     * 当前登录用户资料
     * 详见{@link UserProfile}。
     */
    private UserProfile user;
}
