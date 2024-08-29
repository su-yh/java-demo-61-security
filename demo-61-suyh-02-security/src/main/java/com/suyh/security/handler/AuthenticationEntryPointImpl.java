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
 * 在token 校验失败后会走这里，同时登录校验失败，抛出异常也会走这里。
 * 所以我觉得登录失败了，使用登录失败后置转发url 里面直接处理响应结果就可以了。
 * 而这里主要处理token 校验未通过的问题：包括token 不存在，过期，解析异常等情况。
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
