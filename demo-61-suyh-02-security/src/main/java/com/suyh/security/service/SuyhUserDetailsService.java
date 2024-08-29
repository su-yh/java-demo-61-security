package com.suyh.security.service;

import com.suyh.security.UserToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * @author suyh
 * @since 2023-11-04
 */
@Service("userDetailsService")
@Slf4j
public class SuyhUserDetailsService implements UserDetailsService, LogoutSuccessHandler, UserToken {
    private static final String secret = "fb8b6ef9484b4817af12c1a6edf39262";

    // TODO: suyh - 缓存用户信息

    /**
     * 加载用户信息，主要是在用户登录的时候才会调用，在使用过程中基本都是通过token 来获取登录用户详细信息。
     * 所以这里每次从数据库中查询影响也不大
     *
     * @return
     * @throws UsernameNotFoundException 当用户未找到时直接 抛出该异常即可
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 这个用户所拥有哪些权限
        // admins 是权限，ROLE_sale  是角色名称，ROLE_ 是源代码中要求的前缀
        List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admins,ROLE_sale");

        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String pwd = bCryptPasswordEncoder.encode("123");

        return new User("mary", pwd, auths);
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // TODO: suyh - 用户登出，需要清理相关缓存以及token 失效
    }

    /**
     * token 校验失败，则返回null，不要抛出异常。
     */
    @Override
    @Nullable
    public User loginUserDetail(String token) {
       try {
           // 解析token 得到用户
           Claims claims = parseToken(token);
           if (claims == null) {
               return null;
           }

           String username = claims.getSubject();
           if (!StringUtils.hasText(username)) {
               return null;
           }

           // TODP: suyh - 查询用户是否存在，以及对应的状态是否正常，随后就可以继续了。

           return new User(username, "123", AuthorityUtils.NO_AUTHORITIES);
       } catch (Exception exception) {
           log.error("token authentication failed", exception);
           return null;
       }
    }

    public static String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setSubject(username)
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    public static Claims parseToken(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }
}
