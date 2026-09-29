package install

import "runtime"

// hostOS and hostArch are the running machine's platform, which Install
// selects binaries for by default and List recognizes executables by.
var (
	hostOS   = runtime.GOOS
	hostArch = runtime.GOARCH
)
