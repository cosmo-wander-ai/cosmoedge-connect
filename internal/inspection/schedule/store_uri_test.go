package schedule

import (
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

func TestScheduleFileURIKeepsDriveAndEscapedFilenameOutOfAuthority(t *testing.T) {
	for _, test := range []struct{ name, path, wantPath string }{
		{"windows_drive", "C:/Users/CosmoEdge Connect State/调度 50%+&=.db", "/C:/Users/CosmoEdge Connect State/调度 50%+&=.db"},
		{"posix", "/tmp/CosmoEdge Connect State/调度 50%+&=.db", "/tmp/CosmoEdge Connect State/调度 50%+&=.db"},
		{"posix_literal_backslash", `/tmp/a\b.db`, `/tmp/a\b.db`},
		{"reserved_uri_characters", "C:/state/name?#.db", "/C:/state/name?#.db"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dsn := scheduleFileDSN(test.path)
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(dsn, "file:///") || u.Scheme != "file" || u.Host != "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.Path != test.wantPath {
				t.Fatalf("unexpected SQLite file URI: %q", dsn)
			}
			wantOptions := url.Values{
				"_txlock": {"immediate"},
				"_pragma": {"busy_timeout(5000)", "foreign_keys(1)", "trusted_schema(0)", "synchronous(FULL)", "secure_delete(1)"},
			}
			if !reflect.DeepEqual(u.Query(), wantOptions) {
				t.Fatalf("filename changed SQLite options: %v", u.Query())
			}
		})
	}
}

func TestScheduleStoreOpensExactNativePathWithSpecialCharacters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected", "schedule 调度 50%+&=.db")
	for range 2 {
		store, err := OpenStore(StoreConfig{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		if err := localstate.ValidateFile(path); err != nil {
			t.Fatalf("exact requested database path was not protected: %v", err)
		}
		for pragma, want := range map[string]int{"busy_timeout": 5000, "foreign_keys": 1, "trusted_schema": 0, "synchronous": 2, "secure_delete": 1} {
			var got int
			if err := store.db.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil || got != want {
				t.Fatalf("SQLite option %s = %d, want %d; err=%v", pragma, got, want, err)
			}
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
