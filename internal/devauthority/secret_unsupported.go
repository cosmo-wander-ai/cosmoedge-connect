//go:build !windows

package devauthority

import "errors"

func protectSecret([]byte) ([]byte, error) {
	return nil, errors.New("development device authority requires Windows DPAPI")
}

func unprotectSecret([]byte) ([]byte, error) {
	return nil, errors.New("development device authority requires Windows DPAPI")
}
