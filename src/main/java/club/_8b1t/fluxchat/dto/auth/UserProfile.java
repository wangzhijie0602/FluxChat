package club._8b1t.fluxchat.dto.auth;

import club._8b1t.fluxchat.model.User;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserProfile {
    private Long id;
    private String username;
    private String email;

    public static UserProfile from(User user) {
        return new UserProfile(user.getId(), user.getUsername(), user.getEmail());
    }
}
