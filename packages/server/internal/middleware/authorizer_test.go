package middleware

import (
	"context"
	"testing"
)

func testAuthzConfig() AuthzConfig {
	return AuthzConfig{
		Enabled:     true,
		DefaultRole: "viewer",
		Roles: map[string]Role{
			"admin": {
				Name: "admin",
				Permissions: Permission{
					CanWrite: true, CanRead: true, CanApprove: true, CanAdmin: true,
				},
			},
			"writer": {
				Name: "writer",
				Permissions: Permission{
					AllowedLogTypes: []string{"SYSTEM", "INFRA", "DEBUG"},
					MaxLogLevel:     5,
					CanWrite:        true,
					CanRead:         true,
				},
			},
			"restricted": {
				Name: "restricted",
				Permissions: Permission{
					AllowedLogTypes: []string{"SYSTEM"},
					DeniedLogTypes:  []string{"SECURITY"},
					MaxLogLevel:     3,
					CanWrite:        true,
					CanRead:         true,
				},
			},
			"viewer": {
				Name: "viewer",
				Permissions: Permission{
					CanRead: true,
				},
			},
		},
		ClientRoles: map[string]string{
			"client-admin":      "admin",
			"client-writer":     "writer",
			"client-restricted": "restricted",
		},
	}
}

func TestAuthorizer_Disabled(t *testing.T) {
	authz := NewAuthorizer(AuthzConfig{Enabled: false})

	t.Run("all permissions granted when disabled", func(t *testing.T) {
		ctx, perm, err := authz.Authorize(context.Background(), "anyone")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !perm.CanWrite || !perm.CanRead || !perm.CanApprove || !perm.CanAdmin {
			t.Error("all permissions should be granted when disabled")
		}
		if ClientIDFromContext(ctx) != "anyone" {
			t.Error("clientID should be in context")
		}
	})

	t.Run("write check passes when disabled", func(t *testing.T) {
		if err := authz.CheckWriteLog("anyone", "SECURITY", 6); err != nil {
			t.Errorf("should pass when disabled: %v", err)
		}
	})
}

func TestAuthorizer_AdminRole(t *testing.T) {
	authz := NewAuthorizer(testAuthzConfig())

	t.Run("admin can write any log type", func(t *testing.T) {
		if err := authz.CheckWriteLog("client-admin", "SECURITY", 6); err != nil {
			t.Errorf("admin should write SECURITY: %v", err)
		}
	})

	t.Run("admin can approve", func(t *testing.T) {
		if err := authz.CheckApproval("client-admin"); err != nil {
			t.Errorf("admin should approve: %v", err)
		}
	})

	t.Run("admin can admin", func(t *testing.T) {
		if err := authz.CheckAdmin("client-admin"); err != nil {
			t.Errorf("admin should have admin: %v", err)
		}
	})
}

func TestAuthorizer_WriterRole(t *testing.T) {
	authz := NewAuthorizer(testAuthzConfig())

	t.Run("writer can write allowed types", func(t *testing.T) {
		if err := authz.CheckWriteLog("client-writer", "SYSTEM", 3); err != nil {
			t.Errorf("should write SYSTEM: %v", err)
		}
		if err := authz.CheckWriteLog("client-writer", "INFRA", 4); err != nil {
			t.Errorf("should write INFRA: %v", err)
		}
	})

	t.Run("writer cannot write disallowed types", func(t *testing.T) {
		err := authz.CheckWriteLog("client-writer", "SECURITY", 3)
		if err == nil {
			t.Error("should deny SECURITY for writer")
		}
		authzErr, ok := err.(*AuthzError)
		if !ok {
			t.Fatalf("expected AuthzError, got %T", err)
		}
		if authzErr.Action != "write_log" {
			t.Errorf("expected action write_log, got %s", authzErr.Action)
		}
	})

	t.Run("writer cannot exceed max level", func(t *testing.T) {
		err := authz.CheckWriteLog("client-writer", "SYSTEM", 6)
		if err == nil {
			t.Error("should deny level 6 for writer (max 5)")
		}
	})

	t.Run("writer cannot approve", func(t *testing.T) {
		if err := authz.CheckApproval("client-writer"); err == nil {
			t.Error("writer should not approve")
		}
	})

	t.Run("writer cannot admin", func(t *testing.T) {
		if err := authz.CheckAdmin("client-writer"); err == nil {
			t.Error("writer should not admin")
		}
	})
}

func TestAuthorizer_RestrictedRole(t *testing.T) {
	authz := NewAuthorizer(testAuthzConfig())

	t.Run("restricted can write SYSTEM", func(t *testing.T) {
		if err := authz.CheckWriteLog("client-restricted", "SYSTEM", 3); err != nil {
			t.Errorf("should write SYSTEM: %v", err)
		}
	})

	t.Run("restricted denied SECURITY by deny list", func(t *testing.T) {
		err := authz.CheckWriteLog("client-restricted", "SECURITY", 3)
		if err == nil {
			t.Error("SECURITY should be denied")
		}
	})

	t.Run("restricted cannot exceed max level", func(t *testing.T) {
		err := authz.CheckWriteLog("client-restricted", "SYSTEM", 4)
		if err == nil {
			t.Error("level 4 should be denied (max 3)")
		}
	})
}

func TestAuthorizer_DefaultRole(t *testing.T) {
	authz := NewAuthorizer(testAuthzConfig())

	t.Run("unknown client gets default viewer role", func(t *testing.T) {
		err := authz.CheckWriteLog("unknown-client", "SYSTEM", 1)
		if err == nil {
			t.Error("viewer should not write")
		}
	})

	t.Run("viewer can read but not write", func(t *testing.T) {
		_, perm, err := authz.Authorize(context.Background(), "unknown-client")
		if err != nil {
			t.Fatal(err)
		}
		if !perm.CanRead {
			t.Error("viewer should read")
		}
		if perm.CanWrite {
			t.Error("viewer should not write")
		}
	})
}

func TestAuthorizer_UnknownRole(t *testing.T) {
	cfg := AuthzConfig{
		Enabled:     true,
		DefaultRole: "nonexistent",
		Roles:       map[string]Role{},
		ClientRoles: map[string]string{},
	}
	authz := NewAuthorizer(cfg)

	t.Run("unknown role gets minimum permissions", func(t *testing.T) {
		_, perm, _ := authz.Authorize(context.Background(), "anyone")
		if perm.CanWrite || perm.CanRead || perm.CanApprove || perm.CanAdmin {
			t.Error("unknown role should have no permissions")
		}
	})
}

func TestAuthorizer_ContextValues(t *testing.T) {
	authz := NewAuthorizer(testAuthzConfig())

	ctx, _, _ := authz.Authorize(context.Background(), "client-admin")

	t.Run("clientID in context", func(t *testing.T) {
		id := ClientIDFromContext(ctx)
		if id != "client-admin" {
			t.Errorf("expected client-admin, got %s", id)
		}
	})

	t.Run("permission in context", func(t *testing.T) {
		perm, ok := PermissionFromContext(ctx)
		if !ok {
			t.Fatal("expected permission in context")
		}
		if !perm.CanAdmin {
			t.Error("admin should have CanAdmin in context")
		}
	})
}

func TestAuthorizer_CaseInsensitiveLogType(t *testing.T) {
	authz := NewAuthorizer(testAuthzConfig())

	// Writer has AllowedLogTypes: ["SYSTEM", "INFRA", "DEBUG"]
	// Check case insensitive matching
	t.Run("case insensitive allowed", func(t *testing.T) {
		if err := authz.CheckWriteLog("client-writer", "system", 3); err != nil {
			t.Errorf("should match case-insensitively: %v", err)
		}
	})

	t.Run("case insensitive denied", func(t *testing.T) {
		// Restricted has DeniedLogTypes: ["SECURITY"]
		err := authz.CheckWriteLog("client-restricted", "security", 3)
		if err == nil {
			t.Error("should deny case-insensitively")
		}
	})
}

func TestContextHelpers_Empty(t *testing.T) {
	ctx := context.Background()

	if id := ClientIDFromContext(ctx); id != "" {
		t.Errorf("expected empty, got %s", id)
	}

	_, ok := PermissionFromContext(ctx)
	if ok {
		t.Error("expected no permission")
	}
}
