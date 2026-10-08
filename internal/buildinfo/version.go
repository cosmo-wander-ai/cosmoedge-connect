// Package buildinfo reports the identity embedded in the running executable.
package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"runtime/debug"
)

// Version is set by the paired release builder.
var Version = "development"

// SourceRevision and SourceModified are paired builder inputs. Some Go
// toolchains do not discover Git worktrees through their .git file. The builder
// therefore pins both values from the same source inventory as its manifest.
// Ordinary go builds leave these empty and use Go's VCS metadata instead.
var SourceRevision, SourceModified string

type Info struct {
	Product   string `json:"product"`
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	Modified  bool   `json:"modified"`
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"`
}

// PairingKey binds a request to the service candidate. GoVersion is deliberately
// excluded: the public pairing contract consists of these five build fields.
func (v Info) PairingKey() string {
	raw, _ := json.Marshal([]any{v.Product, v.Version, v.Revision, v.Modified, v.Platform})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func Current() Info {
	var settings []debug.BuildSetting
	if b, ok := debug.ReadBuildInfo(); ok {
		settings = b.Settings
	}
	return currentWithSettings(settings)
}

func currentWithSettings(settings []debug.BuildSetting) Info {
	v := Info{Product: "cosmoedge-connect", Version: Version, GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH}
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			v.Revision = s.Value
		case "vcs.modified":
			v.Modified = s.Value == "true"
		}
	}
	if SourceRevision != "" && (SourceModified == "true" || SourceModified == "false") {
		v.Revision = SourceRevision
		v.Modified = SourceModified == "true"
	}
	return v
}
