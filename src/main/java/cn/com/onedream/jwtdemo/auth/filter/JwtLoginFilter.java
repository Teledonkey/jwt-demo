package cn.com.onedream.jwtdemo.auth.filter;

import cn.com.onedream.jwtdemo.domain.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 模仿UsernamePasswordAuthenticationFilter过滤器做jwt登录认证
 */
public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter {
    public JwtLoginFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher(defaultFilterProcessesUrl));
        setAuthenticationManager(authenticationManager);
    }

    /**
     * 重写验证逻辑
     *
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        //获取request中user对象：用户名和密码
        User user = new ObjectMapper().readValue(request.getInputStream(), User.class);
        //用UsernamePasswordAuthenticationToken创建待认证主体
        UsernamePasswordAuthenticationToken upToken =
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
        //用spring security默认AuthenticationManager进行用户名、密码验证
        return getAuthenticationManager().authenticate(upToken);
    }

    /**
     * 验证成功后返回jwt token
     *
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        //从认证主体中取出所有权限
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        //用于拼接主体中的所有权限，用逗号连接，便于后续过滤器用AuthorityUtils.commaSeparatedStringToAuthorityList()方法创建权限
        StringBuffer as = new StringBuffer();
        for (GrantedAuthority authority :
                authorities) {
            as.append(authority.getAuthority()).append(",");
        }
        //后续用jwt工具类统一处理
        String key = "cuAihCz53DZRjZwbsGcZJ2Ai6At+T142uphtJMsk7iQ=";
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), SignatureAlgorithm.HS512.getJcaName());

        Map<String, StringBuffer> claims = new HashMap<>();
        claims.put("authorities", as);

        String jwt = Jwts.builder()
                .setClaims(claims)
                .setSubject(authResult.getName())
                .setExpiration(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .signWith(secretKey)
                .compact();

        //构造响应数据
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        out.write(new ObjectMapper().writeValueAsString(jwt));
        out.flush();
        out.close();
    }

    /**
     * 验证失败后返回的信息
     *
     * @param request
     * @param response
     * @param failed
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        out.write("登录失败!");
        out.flush();
        out.close();
    }
}
