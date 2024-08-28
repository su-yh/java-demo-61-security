package com.suyh.security.filter;

import com.suyh.security.UserToken;
import com.suyh.security.vo.SuyhAuthenticationToken;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author suyh
 * @since 2024-03-08
 */
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    private final UserToken userToken;

    public JwtAuthenticationTokenFilter(UserToken userToken) {
        this.userToken = userToken;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (StringUtils.hasText(token)) {
            User user = userToken.loginUserDetail(token);
            if (user != null) {
                SuyhAuthenticationToken authenticationToken = new SuyhAuthenticationToken(user);
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // 只要往上下文中添加该实例对象就被认为是认证通过了。
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            } else {
                // token 校验 失败，认证未通过，直接往 下走就可以 了。
                // 它会抛出对应异常，然后继续走到.authenticationEntryPoint(xxx) 这个配置对应 的地方。
                System.out.println("认证失败");
            }
        }

        chain.doFilter(request, response);
    }
}
