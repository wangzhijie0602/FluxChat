package club._8b1t.fluxchat.controller;

import club._8b1t.fluxchat.common.Result;
import club._8b1t.fluxchat.dto.auth.LoginRequest;
import club._8b1t.fluxchat.dto.auth.LoginResponse;
import club._8b1t.fluxchat.dto.auth.RegisterRequest;
import club._8b1t.fluxchat.dto.auth.UserProfile;
import club._8b1t.fluxchat.model.User;
import club._8b1t.fluxchat.service.UserService;
import cn.dev33.satoken.stp.StpUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Authentication APIs
 * 处理用户注册与登录请求，返回统一响应结构。
 *
 * @module Authentication
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    /**
     * Register Account
     * 创建新用户账号，注册成功后返回用户资料。
     *
     * @param request 注册请求参数，详见{@link RegisterRequest}
     * @return 注册结果，data 为用户资料{@link UserProfile}
     */
    @PostMapping("/register")
    public Result<UserProfile> register(@RequestBody RegisterRequest request) {
        User user = userService.register(
                request.getUsername(),
                request.getEmail(),
                request.getPassword(),
                request.getConfirmPassword()
        );
        return Result.success("注册成功", UserProfile.from(user));
    }

    /**
     * Login
     * 使用账号与密码进行认证，认证通过后签发 Token 并返回当前用户资料。
     *
     * @param request 登录请求参数，详见{@link LoginRequest}
     * @return 登录结果，data 为登录信息{@link LoginResponse}
     */
    @PostMapping("/login")
    public Result<LoginResponse> login(@RequestBody LoginRequest request) {
        User user = userService.authenticate(request.getAccount(), request.getPassword());
        StpUtil.login(user.getId());
        LoginResponse response = new LoginResponse(StpUtil.getTokenInfo(), UserProfile.from(user));
        return Result.success("登录成功", response);
    }
}
