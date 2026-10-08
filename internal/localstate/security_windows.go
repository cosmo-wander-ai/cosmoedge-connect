//go:build windows

package localstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func PrepareStateRoot(path string) error {
	if path == "" {
		return os.ErrInvalid
	}
	if _, err := os.Lstat(path); err == nil {
		return ValidateStateRoot(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// MkdirAll does not apply protected DACLs to intermediate directories.
	// Create every missing directory with its final protected DACL atomically,
	// so concurrent openers cannot observe a Mkdir/harden gap. Existing paths
	// are only validated, never repaired.
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	var missing []string
	for current := absolute; ; current = filepath.Dir(current) {
		if _, err := os.Lstat(current); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		if filepath.Dir(current) == current {
			return errors.New("Operator state root has no existing ancestor")
		}
	}
	for index := len(missing) - 1; index >= 0; index-- {
		current := missing[index]
		if err := createPrivateDirectory(current); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := ValidateStateRoot(current); err != nil {
			return err
		}
	}
	return ValidateStateRoot(path)
}

// createPrivateDirectory attaches owner and DACL during CreateDirectoryW,
// rather than exposing an inherited ACL until a later SetNamedSecurityInfo.
func createPrivateDirectory(path string) error {
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	sid := user.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	return windows.CreateDirectory(name, &attributes)
}

func ValidateStateRoot(path string) error {
	return validatePath(path, true)
}

func ProtectFile(path string) error {
	if err := harden(path, false); err != nil {
		return fmt.Errorf("protect Operator state file: %w", err)
	}
	return ValidateFile(path)
}

func ValidateFile(path string) error {
	return validatePath(path, false)
}

func ValidateExistingStateFiles(root string) error {
	for _, name := range []string{"owner.lock", "locator.json", "operator.db", "operator.db-wal", "operator.db-shm"} {
		path := filepath.Join(root, name)
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := ValidateFile(path); err != nil {
			return fmt.Errorf("reject existing Operator state file %s: %w", name, err)
		}
	}
	return nil
}

func validatePath(path string, directory bool) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("Operator state must not be a reparse point")
	}
	if directory != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return errors.New("Operator state path has an unexpected object type")
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("Operator state must have a protected DACL")
	}
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(user) {
		return errors.New("Operator state must be owned by the current Windows user")
	}
	dacl, defaulted, err := sd.DACL()
	if err != nil || dacl == nil || defaulted || dacl.AceCount == 0 {
		return errors.New("Operator state must have an explicit current-user DACL")
	}
	grantsControl := false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return errors.New("Operator state DACL must contain non-inherited allow entries only")
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !aceSID.IsValid() || !aceSID.Equals(user) {
			return errors.New("Operator state DACL grants another principal")
		}
		required := windows.ACCESS_MASK(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC)
		if (ace.Mask&windows.GENERIC_ALL != 0 || ace.Mask&required == required) && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
			grantsControl = true
		}
	}
	if !grantsControl {
		return errors.New("Operator state DACL does not grant current-user control")
	}
	return nil
}

func harden(path string, directory bool) error {
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user),
		},
	}}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		user,
		nil,
		acl,
		nil,
	)
}

func currentUserSID() (*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}
