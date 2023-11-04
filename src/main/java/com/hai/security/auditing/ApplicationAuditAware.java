package com.hai.security.auditing;

import com.hai.security.user.User;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class ApplicationAuditAware implements AuditorAware<Integer> {
    // Đây là một lớp triển khai của AuditorAware, được sử dụng để xác định người dùng thực hiện thao tác kiểm tra (audit).

    @Override
    public Optional<Integer> getCurrentAuditor() {
        // Phương thức này được gọi để xác định người dùng hiện tại thực hiện thao tác kiểm tra (audit).

        Authentication authentication =
                SecurityContextHolder
                        .getContext()
                        .getAuthentication();
        // Lấy thông tin xác thực (authentication) hiện tại từ SecurityContextHolder, nơi lưu trữ thông tin xác thực.

        if (authentication == null ||
                !authentication.isAuthenticated() ||
                authentication instanceof AnonymousAuthenticationToken
        ) {
            // Kiểm tra xem thông tin xác thực có tồn tại (không null) và đã được xác thực.
            // Nếu không có thông tin xác thực hoặc thông tin xác thực không được xác thực (isAuthenticated() trả về false) hoặc
            // thông tin xác thực là một phiên bản AnonymousAuthenticationToken (phiên bản dùng cho người dùng không xác thực), thì:
            return Optional.empty();
            // Trả về một Optional rỗng để chỉ định rằng không có người dùng nào thực hiện thao tác kiểm tra (audit).
        }

        User userPrincipal = (User) authentication.getPrincipal();
        // Lấy thông tin người dùng (User) từ phần tử chính (principal) trong thông tin xác thực (authentication).

        return Optional.ofNullable(userPrincipal.getId());
        // Trả về Optional chứa ID của người dùng. Phương thức ofNullable cho phép bạn truyền giá trị có thể là null.
    }
}
