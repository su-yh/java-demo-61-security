package com.suyh.security.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 认证失败的后置处理
 * 也就是说对于需要 登录的url，需要校验token 是否正确，如果不正确则会在拦截并走到此处。
 * 让其重新登录
 *
 * @author suyh
 * @since 2024-03-08
 */
@Slf4j
public class AuthenticationEntryPointImpl
        implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) {
        log.debug("[commence][访问 URL({}) 时，没有登录]", request.getRequestURI());
        // response.sendError(HttpStatus.UNAUTHORIZED.value());
        throw new RuntimeException("未认证");
    }
}
