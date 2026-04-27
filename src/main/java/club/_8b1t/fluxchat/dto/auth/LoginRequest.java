package club._8b1t.fluxchat.dto.auth;

import lombok.Data;

/**
 * 登录请求参数
 * 用于接收登录接口的请求体数据。
 *
 * @module Authentication
 */
@Data
public class LoginRequest {
    /**
     * 登录账号
     * 支持用户名或邮箱。
     */
    private String account;

    /**
     * 登录密码
     * 明文由客户端传入，服务端负责校验。
     */
    private String password;
}
