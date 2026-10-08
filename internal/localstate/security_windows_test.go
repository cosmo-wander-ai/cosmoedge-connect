//go:build windows

package localstate

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsStateDACLPositiveNegativeMatrix(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Operator")
	if err := PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "locator.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	if err := ValidateStateRoot(root); err != nil {
		t.Fatalf("protected root rejected: %v", err)
	}
	if err := ValidateFile(path); err != nil {
		t.Fatalf("protected file rejected: %v", err)
	}

	user, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	setTestDACL(t, path, true,
		testAllow(user, windows.GENERIC_ALL, windows.NO_INHERITANCE),
		testAllow(everyone, windows.GENERIC_READ, windows.NO_INHERITANCE),
	)
	if err := ValidateFile(path); err == nil {
		t.Fatal("file granting Everyone access was accepted")
	}
	if err := ValidateExistingStateFiles(root); err == nil {
		t.Fatal("existing unsafe Operator state was accepted")
	}

	setTestDACL(t, root, true, testAllow(user, windows.GENERIC_ALL, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT))
	inherited := filepath.Join(root, "inherited.json")
	if err := os.WriteFile(inherited, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFile(inherited); err == nil {
		t.Fatal("file with inherited access was accepted")
	}
	if err := ProtectFile(inherited); err != nil {
		t.Fatal(err)
	}
}

func testAllow(sid *windows.SID, permissions windows.ACCESS_MASK, inheritance uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: permissions,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func setTestDACL(t *testing.T, path string, protected bool, entries ...windows.EXPLICIT_ACCESS) {
	t.Helper()
	user, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if protected {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, user, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsNestedStateRootsProtectEveryCreatedDirectory(t *testing.T) {
	if err := PrepareStateRoot(""); err == nil {
		t.Fatal("empty state root accepted")
	}
	ambient := t.TempDir()
	product := filepath.Join(ambient, "inspection-v2")
	credentials := filepath.Join(product, "credentials")
	if err := PrepareStateRoot(credentials); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{product, credentials} {
		if err := ValidateStateRoot(root); err != nil {
			t.Fatalf("new directory was left unprotected: %v", err)
		}
	}
	if err := PrepareStateRoot(product); err != nil {
		t.Fatalf("sibling state cannot reuse product root: %v", err)
	}
	// Existing ambient paths are never silently repaired while creating below them.
	if err := ValidateStateRoot(ambient); err == nil {
		t.Fatal("ambient directory was silently hardened")
	}
	if err := PrepareStateRoot(ambient); err == nil {
		t.Fatal("existing unprotected directory accepted")
	}
}

func TestWindowsConcurrentStateRootCreationIsPrivateImmediately(t *testing.T) {
	for round := 0; round < 8; round++ {
		root := filepath.Join(t.TempDir(), fmt.Sprintf("concurrent-%d", round), "state")
		start := make(chan struct{})
		results := make(chan error, 8)
		for worker := 0; worker < cap(results); worker++ {
			go func() {
				<-start
				err := PrepareStateRoot(root)
				if err == nil {
					err = ValidateStateRoot(root)
				}
				results <- err
			}()
		}
		close(start)
		for worker := 0; worker < cap(results); worker++ {
			if err := <-results; err != nil {
				t.Errorf("round %d concurrent creation: %v", round, err)
			}
		}
	}
}
