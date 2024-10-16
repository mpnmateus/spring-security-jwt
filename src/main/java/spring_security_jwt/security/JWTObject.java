package spring_security_jwt.security;

import java.util.Date;
import java.util.List;

//Estrutura de objeto que será convertido em um token
public class JWTObject {
    private String subject; //nome do usuário
    private Date issueAdt; //data de criação do token
    private Date expiration; //data de expiração do token
    private List<String> roles;

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public Date getIssueAdt() {
        return issueAdt;
    }

    public void setIssueAdt(Date issueAdt) {
        this.issueAdt = issueAdt;
    }

    public Date getExpiration() {
        return expiration;
    }

    public void setExpiration(Date expiration) {
        this.expiration = expiration;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
