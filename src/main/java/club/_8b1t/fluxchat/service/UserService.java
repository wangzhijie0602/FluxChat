package club._8b1t.fluxchat.service;

import club._8b1t.fluxchat.mapper.UserMapper;
import club._8b1t.fluxchat.exception.BusinessException;
import club._8b1t.fluxchat.model.User;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Pattern;

@Service
public class UserService {

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{4,32}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,63}$");
    private static final Pattern PASSWORD_LETTER_PATTERN = Pattern.compile(".*[A-Za-z].*");
    private static final Pattern PASSWORD_DIGIT_PATTERN = Pattern.compile(".*\\d.*");
    private static final int PASSWORD_MIN_LENGTH = 8;
    private static final int PASSWORD_MAX_LENGTH = 64;
    private static final int PBKDF2_ITERATIONS = 120_000;
    private static final int SALT_LENGTH_BYTES = 16;
    private static final int HASH_LENGTH_BYTES = 32;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";

    private final UserMapper userMapper;

    public UserService(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @Transactional
    public User register(String username, String email, String password, String confirmPassword) {
        String normalizedUsername = normalizeUsername(username);
        String normalizedEmail = normalizeEmail(email);
        validatePasswordForRegister(password, confirmPassword);

        if (existsByUsername(normalizedUsername)) {
            throw new BusinessException(400, "用户名已存在");
        }
        if (existsByEmail(normalizedEmail)) {
            throw new BusinessException(400, "邮箱已被使用");
        }

        String passwordHash = hashPassword(password);
        User user = new User();
        user.setUsername(normalizedUsername);
        user.setEmail(normalizedEmail);
        user.setPasswordHash(passwordHash);
        user.setIsDeleted(0);

        try {
            int updatedRows = userMapper.insert(user);
            if (updatedRows != 1 || user.getId() == null) {
                throw new BusinessException(500, "注册失败，请稍后重试");
            }
        } catch (DuplicateKeyException e) {
            throw new BusinessException(400, "用户名或邮箱已存在");
        }

        return user;
    }

    public User authenticate(String account, String password) {
        String normalizedAccount = normalizeAccount(account);
        if (!StringUtils.hasText(password)) {
            throw new BusinessException(400, "密码不能为空");
        }

        User user = findByAccount(normalizedAccount);
        if (user == null) {
            throw new BusinessException(401, "账号或密码错误");
        }
        if (user.getIsDeleted() != null && user.getIsDeleted() == 1) {
            throw new BusinessException(403, "账号已被注销");
        }
        if (!matchesPassword(password, user.getPasswordHash())) {
            throw new BusinessException(401, "账号或密码错误");
        }
        return user;
    }

    private String normalizeUsername(String username) {
        if (!StringUtils.hasText(username)) {
            throw new BusinessException(400, "用户名不能为空");
        }
        String normalizedUsername = username.trim();
        if (!USERNAME_PATTERN.matcher(normalizedUsername).matches()) {
            throw new BusinessException(400, "用户名需为4-32位，仅支持字母、数字和下划线");
        }
        return normalizedUsername;
    }

    private String normalizeEmail(String email) {
        if (!StringUtils.hasText(email)) {
            throw new BusinessException(400, "邮箱不能为空");
        }
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        if (!EMAIL_PATTERN.matcher(normalizedEmail).matches()) {
            throw new BusinessException(400, "邮箱格式不正确");
        }
        return normalizedEmail;
    }

    private String normalizeAccount(String account) {
        if (!StringUtils.hasText(account)) {
            throw new BusinessException(400, "账号不能为空");
        }
        String normalizedAccount = account.trim();
        if (normalizedAccount.contains("@")) {
            return normalizeEmail(normalizedAccount);
        }
        return normalizeUsername(normalizedAccount);
    }

    private void validatePasswordForRegister(String password, String confirmPassword) {
        if (!StringUtils.hasText(password) || !StringUtils.hasText(confirmPassword)) {
            throw new BusinessException(400, "密码和确认密码不能为空");
        }
        if (!password.equals(confirmPassword)) {
            throw new BusinessException(400, "两次输入的密码不一致");
        }
        if (password.length() < PASSWORD_MIN_LENGTH || password.length() > PASSWORD_MAX_LENGTH) {
            throw new BusinessException(400, "密码长度需在8-64位之间");
        }
        if (!PASSWORD_LETTER_PATTERN.matcher(password).matches() || !PASSWORD_DIGIT_PATTERN.matcher(password).matches()) {
            throw new BusinessException(400, "密码需同时包含字母和数字");
        }
    }

    private boolean existsByUsername(String username) {
        Long count = userMapper.selectCount(
                new LambdaQueryWrapper<User>()
                        .eq(User::getUsername, username)
        );
        return count != null && count > 0;
    }

    private boolean existsByEmail(String email) {
        Long count = userMapper.selectCount(
                new LambdaQueryWrapper<User>()
                        .eq(User::getEmail, email)
        );
        return count != null && count > 0;
    }

    private User findByAccount(String account) {
        boolean isEmail = account.contains("@");
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        if (isEmail) {
            queryWrapper.eq(User::getEmail, account);
        } else {
            queryWrapper.eq(User::getUsername, account);
        }
        queryWrapper.last("LIMIT 1");
        return userMapper.selectOne(queryWrapper);
    }

    private String hashPassword(String rawPassword) {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        byte[] hash = pbkdf2(rawPassword.toCharArray(), salt, PBKDF2_ITERATIONS, HASH_LENGTH_BYTES);
        return "pbkdf2$"
                + PBKDF2_ITERATIONS
                + "$"
                + Base64.getEncoder().encodeToString(salt)
                + "$"
                + Base64.getEncoder().encodeToString(hash);
    }

    private boolean matchesPassword(String rawPassword, String storedHash) {
        if (!StringUtils.hasText(storedHash)) {
            return false;
        }
        String[] parts = storedHash.split("\\$");
        if (parts.length != 4 || !"pbkdf2".equals(parts[0])) {
            return false;
        }
        try {
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expectedHash = Base64.getDecoder().decode(parts[3]);
            byte[] actualHash = pbkdf2(rawPassword.toCharArray(), salt, iterations, expectedHash.length);
            return MessageDigest.isEqual(expectedHash, actualHash);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private byte[] pbkdf2(char[] password, byte[] salt, int iterations, int hashLengthBytes) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, hashLengthBytes * 8);
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            return secretKeyFactory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new BusinessException(500, "密码加密失败，请联系管理员");
        } finally {
            spec.clearPassword();
        }
    }

}
