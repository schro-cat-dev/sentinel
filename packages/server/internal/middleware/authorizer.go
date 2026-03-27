package middleware

import (
	"context"
	"fmt"
	"strings"
)

// Permission はクライアントに許可された操作の粒度
type Permission struct {
	AllowedLogTypes []string `json:"allowed_log_types"` // 空=全許可
	DeniedLogTypes  []string `json:"denied_log_types"`  // 明示的拒否
	MaxLogLevel     int      `json:"max_log_level"`     // 0=無制限、送信可能な最大レベル
	CanWrite        bool     `json:"can_write"`         // ログ書き込み権限
	CanRead         bool     `json:"can_read"`          // ログ読み取り権限
	CanApprove      bool     `json:"can_approve"`       // 承認権限
	CanAdmin        bool     `json:"can_admin"`         // 管理者権限
}

// Role はロール定義
type Role struct {
	Name        string     `json:"name"`
	Permissions Permission `json:"permissions"`
}

// AuthzConfig は認可設定
type AuthzConfig struct {
	Enabled       bool              `json:"enabled"`
	DefaultRole   string            `json:"default_role"`
	Roles         map[string]Role   `json:"roles"`
	ClientRoles   map[string]string `json:"client_roles"` // clientID → roleName
}

// contextKey は認可コンテキストキー
type contextKey string

const (
	ctxKeyClientID   contextKey = "client_id"
	ctxKeyPermission contextKey = "permission"
)

// ContextWithClientID はコンテキストにクライアントIDを設定する
func ContextWithClientID(ctx context.Context, clientID string) context.Context {
	return context.WithValue(ctx, ctxKeyClientID, clientID)
}

// ClientIDFromContext はコンテキストからクライアントIDを取得する
func ClientIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyClientID).(string); ok {
		return v
	}
	return ""
}

// ContextWithPermission はコンテキストに権限を設定する
func ContextWithPermission(ctx context.Context, perm Permission) context.Context {
	return context.WithValue(ctx, ctxKeyPermission, perm)
}

// PermissionFromContext はコンテキストから権限を取得する
func PermissionFromContext(ctx context.Context) (Permission, bool) {
	perm, ok := ctx.Value(ctxKeyPermission).(Permission)
	return perm, ok
}

// AuthzError は認可エラー
type AuthzError struct {
	ClientID string
	Action   string
	Reason   string
}

func (e *AuthzError) Error() string {
	return fmt.Sprintf("authz denied: client=%s action=%s reason=%s", e.ClientID, e.Action, e.Reason)
}

// Authorizer はRBACベースの認可を行う
type Authorizer struct {
	config AuthzConfig
}

// NewAuthorizer はAuthorizerを生成する
func NewAuthorizer(cfg AuthzConfig) *Authorizer {
	return &Authorizer{config: cfg}
}

// Authorize はクライアントIDに基づいて権限を解決し、コンテキストに設定する
func (a *Authorizer) Authorize(ctx context.Context, clientID string) (context.Context, *Permission, error) {
	if !a.config.Enabled {
		perm := &Permission{
			CanWrite: true, CanRead: true, CanApprove: true, CanAdmin: true,
		}
		ctx = ContextWithClientID(ctx, clientID)
		ctx = ContextWithPermission(ctx, *perm)
		return ctx, perm, nil
	}

	perm := a.resolvePermission(clientID)
	ctx = ContextWithClientID(ctx, clientID)
	ctx = ContextWithPermission(ctx, *perm)
	return ctx, perm, nil
}

// CheckWriteLog はログ書き込み権限を検証する
func (a *Authorizer) CheckWriteLog(clientID string, logType string, logLevel int) error {
	if !a.config.Enabled {
		return nil
	}

	perm := a.resolvePermission(clientID)

	if !perm.CanWrite {
		return &AuthzError{ClientID: clientID, Action: "write_log", Reason: "write permission denied"}
	}

	// LogType検証
	if len(perm.DeniedLogTypes) > 0 {
		for _, denied := range perm.DeniedLogTypes {
			if strings.EqualFold(denied, logType) {
				return &AuthzError{ClientID: clientID, Action: "write_log", Reason: fmt.Sprintf("log type %s is denied", logType)}
			}
		}
	}

	if len(perm.AllowedLogTypes) > 0 {
		allowed := false
		for _, a := range perm.AllowedLogTypes {
			if strings.EqualFold(a, logType) {
				allowed = true
				break
			}
		}
		if !allowed {
			return &AuthzError{ClientID: clientID, Action: "write_log", Reason: fmt.Sprintf("log type %s not allowed", logType)}
		}
	}

	// LogLevel検証
	if perm.MaxLogLevel > 0 && logLevel > perm.MaxLogLevel {
		return &AuthzError{ClientID: clientID, Action: "write_log", Reason: fmt.Sprintf("log level %d exceeds max %d", logLevel, perm.MaxLogLevel)}
	}

	return nil
}

// CheckApproval は承認権限を検証する
func (a *Authorizer) CheckApproval(clientID string) error {
	if !a.config.Enabled {
		return nil
	}
	perm := a.resolvePermission(clientID)
	if !perm.CanApprove {
		return &AuthzError{ClientID: clientID, Action: "approve", Reason: "approval permission denied"}
	}
	return nil
}

// CheckAdmin は管理者権限を検証する
func (a *Authorizer) CheckAdmin(clientID string) error {
	if !a.config.Enabled {
		return nil
	}
	perm := a.resolvePermission(clientID)
	if !perm.CanAdmin {
		return &AuthzError{ClientID: clientID, Action: "admin", Reason: "admin permission denied"}
	}
	return nil
}

func (a *Authorizer) resolvePermission(clientID string) *Permission {
	roleName := a.config.DefaultRole
	if mapped, ok := a.config.ClientRoles[clientID]; ok {
		roleName = mapped
	}

	if role, ok := a.config.Roles[roleName]; ok {
		return &role.Permissions
	}

	// ロールが見つからない場合は最小権限
	return &Permission{
		CanWrite: false, CanRead: false, CanApprove: false, CanAdmin: false,
	}
}
