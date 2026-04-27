package club._8b1t.fluxchat.dto.auth;

import lombok.Data;

/**
 * 注册请求参数
 * 用于接收注册接口的请求体数据。
 *
 * @module Authentication
 */
@Data
public class RegisterRequest {
    /**
     * 用户名
     * 用于系统内展示和登录识别。
     */
    private String username;

    /**
     * 邮箱
     * 作为用户联系信息及可选登录账号。
     */
    private String email;

    /**
     * 密码
     * 用户输入的登录凭据。
     */
    private String password;

    /**
     * 确认密码
     * 需与{@link #password}保持一致。
     */
    private String confirmPassword;
}
