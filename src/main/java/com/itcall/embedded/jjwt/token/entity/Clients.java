package com.itcall.embedded.jjwt.token.entity;

import java.io.Serializable;

import org.springframework.data.annotation.Id;
import org.springframework.security.core.SpringSecurityCoreVersion;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "tbl_client_info")
public class Clients implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long seq;

	private String clientId;

	private String clientSecret;

	private String scope;

	private String resourceIds;

	private String authorizedGrantTypes;

	private String registeredRedirectUris;

	private String autoApproveScopes;

	private String authorities;

	private Integer accessTokenValiditySeconds;

	private Integer refreshTokenValiditySeconds;

	@Override
	public String toString() {
		return "Clients{" + "seq=" + seq + ", clientId='" + clientId + '\'' + ", clientSecret='" + clientSecret + '\''
				+ ", scope='" + scope + '\'' + ", resourceIds='" + resourceIds + '\'' + ", authorizedGrantTypes='"
				+ authorizedGrantTypes + '\'' + ", registeredRedirectUris='" + registeredRedirectUris + '\''
				+ ", autoApproveScopes='" + autoApproveScopes + '\'' + ", authorities='" + authorities + '\''
				+ ", accessTokenValiditySeconds=" + accessTokenValiditySeconds + ", refreshTokenValiditySeconds="
				+ refreshTokenValiditySeconds + '}';
	}
}
