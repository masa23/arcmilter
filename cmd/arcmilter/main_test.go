package main

import (
	"errors"
	"math/rand"
	"os"
	"strconv"
	"syscall"
	"testing"
)

func Test_checkPidFile(t *testing.T) {
	pidFile := "test.pid"
	defer func() {
		if err := os.Remove(pidFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed to remove pid file: %v", err)
		}
	}()
	// remove pid file
	if err := os.Remove(pidFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed to remove pid file: %v", err)
	}
	testCases := []struct {
		name      string
		fileExist bool
		pidExist  bool
		expectErr bool
	}{
		{
			name:      "no pid file",
			fileExist: false,
			pidExist:  false,
			expectErr: false,
		},
		{
			name:      "pid file exists no process",
			fileExist: true,
			pidExist:  false,
			expectErr: false,
		},
		{
			name:      "pid file exists process exists",
			fileExist: true,
			pidExist:  true,
			expectErr: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.fileExist {
				var pidStr string

				// PIDがある場合のテストは、test実行のpidを書き込む
				if tt.pidExist {
					pid := os.Getpid()
					pidStr = strconv.Itoa(pid)
				} else {
					for {
						randPid := rand.Intn(9000) + 1000
						if err := syscall.Kill(randPid, 0); err == nil {
							continue
						}
						pidStr = strconv.Itoa(randPid)
						break
					}
				}

				if err := os.WriteFile(pidFile, []byte(pidStr), 0644); err != nil {
					t.Fatalf("failed to write pid file: %v", err)
				}
			}
			err := checkPidFile(pidFile)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
