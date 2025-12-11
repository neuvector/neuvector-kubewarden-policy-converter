package internal

import (
	"fmt"
	"runtime"
)

var (
	// Version holds the version of nvrules2kw, this is set at build time.
	Version string //nolint:gochecknoglobals // this is a variable set at build time
	// BuildDate holds the date during which the nvrules2kw binary was built, this is set at build time.
	BuildDate string //nolint:gochecknoglobals // this is a variable set at build time
	// Tag holds the git tag defined on nvrules2kw repo when the binary was built, this is set at build time.
	Tag string //nolint:gochecknoglobals // this is a variable set at build time
	// ClosestTag holds the closest git tag defined on nvrules2kw repo when the binary was built, this is set at build time.
	ClosestTag string //nolint:gochecknoglobals // this is a variable set at build time
)

// NVrules2kwVersion holds the build-time information of nvrules2kw.
type NVrules2kwVersion struct {
	Version   string
	BuildDate string
	Tag       string
	GoVersion string
}

// CurrentVersion returns the information about the current version of nvrules2kw.
func CurrentVersion() NVrules2kwVersion {
	nvrules2kwVersion := NVrules2kwVersion{
		Version:   Version,
		BuildDate: BuildDate,
		Tag:       Tag,
		GoVersion: runtime.Version(),
	}
	if nvrules2kwVersion.Tag == "" {
		nvrules2kwVersion.Version = fmt.Sprintf("untagged (%s)", ClosestTag)
	}
	return nvrules2kwVersion
}

// String returns the version information nicely formatted.
func (s NVrules2kwVersion) String() string {
	if s.Tag == "" {
		return fmt.Sprintf("nvrules2kw version: %s %s %s", s.Version, s.BuildDate, s.GoVersion)
	}
	return fmt.Sprintf("nvrules2kw version: %s (tagged as %q) %s %s", s.Version, s.Tag, s.BuildDate, s.GoVersion)
}
