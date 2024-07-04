package com.itcall.embedded.jjwt.token.entity;

import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.Date;

import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.Comment;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Transient;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.AuthorityUtils;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.Basic;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@DynamicInsert
@ToString
@Getter
@Setter
@Entity
@Table(name = "tbl_user_info"
//        uniqueConstraints = @UniqueConstraint(name = "uk_tbl_merge_hist_01", columnNames = {"project_id","updated_id"}),
//        indexes = @Index(name = "idx_tbl_merge_hist_01", columnList = "project_id", unique = false /*** Unique가 가능한 경우 true를 주세요. 더 빨라져요.***/)
)
@Comment("사용자 테이블")
@SQLRestriction(value = "is_deleted = false")
@SQLDelete(sql = "UPDATE tbl_user SET is_deleted = true where id = ?")
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@NoArgsConstructor
public class UsersEntity implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	@Comment("사용자 관리 아이디")
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Comment("사용자 로그인 이름")
	@Column(unique = true)
	private String username;

	// @Convert(converter = JpaShaConverter.class) // 이미 해쉬처리된 데이터는 그대로 전달하고, 이외 평문은
	// 해쉬화(암호화) 처리 후 DB로 전달한다.
	@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
	@Comment("사용자 로그인 패스워드")
	@Column
	private String password;

	@Comment("사용자 이름")
	@Column
	private String name;

	@Comment("사용자 이메일")
	@Column
	private String email;

	@Comment("사용자 모바일 번호")
	@Column
	private String mobile;

	@Comment("사용자 역할, Comma구분")
	@Column
	private String roles;

	@Comment("계정 만료")
	@Column
	@ColumnDefault("false")
	private boolean accountExpired;

	@Comment("계정 잠금")
	@Column
	@ColumnDefault("false")
	private boolean accountLocked;

	@Comment("인증 만료")
	@Column
	@ColumnDefault("false")
	private boolean credentialsExpired;

	@Comment("사용 가능")
	@Column(name = "is_enabled")
	@ColumnDefault("false")
	private boolean enabled;

	@Comment("로그인 실패 카운트")
	@Column
	@ColumnDefault("0")
	private Integer loginFailCount;

	@Comment("마지막 패스워드 변경 날짜")
	@Column
	@Temporal(TemporalType.TIMESTAMP)
	private Date lastPasswordChangeDate;

	@Column(name = "is_admin")
	@ColumnDefault("false")
	private boolean isAdmin;

	@Comment("부서명")
	private String deptNm; // 부서명
	@Comment("소속")
	private String brNm; // 소속

	private String databaseConnectionCount;

	@Comment("형상서버 로그인 이름")
	@Column
	private String gitUsername;

	@Comment("형상서버 사용자 토큰")
	@Column
	private String gitUserToken;

	@Comment("형상서버 사용자 토큰 만료")
	@Column
	private Date gitUserTokenExpireDate;

	@Comment("형상서버 로그인 이름")
	@Column
	private Long scmUserId;

	@Comment("형상서버 로그인 이름")
	@Column
	private String scmUsername;

	@Comment("형상서버 사용자 토큰")
	@Column
	private String scmUserToken;

	@Comment("형상서버 사용자 토큰 만료")
	@Column
	private Date scmUserTokenExpireDate;

	@Basic
	@Comment("승인 상태")
	@Column(name = "join_status")
	private Character userJoinStatusEnumValue;

	@Comment("삭제 여부")
	@Column(name = "is_deleted", nullable = false)
	@ColumnDefault("false")
	private Boolean isDeleted;

	@Transient
	private String keyword;

	@Transient
	private Boolean isRegistered;

	@Transient
	private Boolean isPasswordReset;

	@Transient
	private Date lastLoginAt;

	/**
	 * <pre>
	 * 권한이 한 사용자에 여러개 들어갈 수 있는 구조로 바뀌어야 한다.
	 * </pre>
	 * 
	 * @author KUEE-HAENG LEE
	 * @return
	 */
	@Transient
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return AuthorityUtils.commaSeparatedStringToAuthorityList(this.roles);
	}

	/**
	 * 수정자 아이디
	 */
	@LastModifiedBy
	@Column(name = "updated_by", length = 256, insertable = false)
	@Comment("수정자아이디")
	private String updatedBy;

	/**
	 * 수정일자
	 */
	@LastModifiedDate
	@Column(name = "updated_at", insertable = false) // , columnDefinition = "TIMESTAMP WITH TIME ZONE")
	@Comment("수정일시")
	private OffsetDateTime updatedAt;

	/**
	 * 생성자/등록자 이이디
	 */
	@CreatedBy
	@Column(name = "created_by", length = 256, updatable = false) // columnDefinition = "varchar(256) // comment
																	// '등록자아이디'" <== MySQL
	@Comment("등록자아이디")
	private String createdBy;

	/**
	 * 생성일자/등록일자
	 */
	@CreatedDate
	@ColumnDefault("now()")
	@Column(name = "created_at", updatable = false, nullable = false, columnDefinition = "TIMESTAMP WITH TIME ZONE")
	@Comment("등록일시")
	private OffsetDateTime createdAt;

}