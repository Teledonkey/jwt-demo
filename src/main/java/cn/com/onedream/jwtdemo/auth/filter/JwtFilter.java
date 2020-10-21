package cn.com.onedream.jwtdemo.auth.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * 用于验证请求中的jwt token
 */
public class JwtFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        //获取请求request.header中的权限
        String jwtToken = request.getHeader("authorities");
        //后续用jwt工具类统一处理
        String key = "cuAihCz53DZRjZwbsGcZJ2Ai6At+T142uphtJMsk7iQ=";
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), SignatureAlgorithm.HS512.getJcaName());

        //解析jwt token中的信息
        Claims claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(jwtToken).getBody();
        String username = claims.getSubject();
        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get("authorities"));
        //创建带权限的UsernamePasswordAuthenticationToken，后续过滤器将不会再验证主体
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
        //将验证后的主体放入SecurityContext，供后续鉴权过滤器FilterSecurityInterceptor使用
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request,response);

    }
}
