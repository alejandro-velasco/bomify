package buildinfo

var (
	version   = "dev"
	commit    = "unknown"
	date      = "unknown"
	goVersion = "unknown"
)

type buildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"goVersion"`
}

func GetBuildInfo() buildInfo {
	return buildInfo{
		Version:   version,
		Commit:    commit,
		Date:      date,
		GoVersion: goVersion,
	}
}
