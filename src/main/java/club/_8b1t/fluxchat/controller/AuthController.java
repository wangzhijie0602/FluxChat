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

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    /**
     * 用户注册
     * 创建新用户账号并返回用户基础信息。
     *
     * @param request 注册请求体，包含用户名、邮箱、密码与确认密码
     * @return 注册结果，成功时返回用户资料
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
     * 用户登录
     * 使用账号与密码进行身份认证，认证通过后签发登录 Token。
     *
     * @param request 登录请求体，包含账号（用户名或邮箱）与密码
     * @return 登录结果，成功时返回 Token 信息与用户资料
     */
    @PostMapping("/login")
    public Result<LoginResponse> login(@RequestBody LoginRequest request) {
        User user = userService.authenticate(request.getAccount(), request.getPassword());
        StpUtil.login(user.getId());
        LoginResponse response = new LoginResponse(StpUtil.getTokenInfo(), UserProfile.from(user));
        return Result.success("登录成功", response);
    }
}
