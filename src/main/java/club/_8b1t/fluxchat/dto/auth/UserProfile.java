package club._8b1t.fluxchat.dto.auth;

import club._8b1t.fluxchat.model.User;
import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * 用户资料
 * 认证相关接口返回的基础用户信息。
 *
 * @module Authentication
 */
@Data
@AllArgsConstructor
public class UserProfile {
    /**
     * 用户 ID
     * 系统内唯一标识。
     */
    private Long id;

    /**
     * 用户名
     * 用户在系统中的显示名称。
     */
    private String username;

    /**
     * 邮箱
     * 用户绑定的邮箱地址。
     */
    private String email;

    /**
     * 从用户实体转换为用户资料对象。
     *
     * @param user 用户实体，详见{@link User}
     * @return 用户资料对象{@link UserProfile}
     */
    public static UserProfile from(User user) {
        return new UserProfile(user.getId(), user.getUsername(), user.getEmail());
    }
}
