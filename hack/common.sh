# Shell helpers shared by the build: sourced by hack/*.sh and the
# Makefile's recipes (which run /bin/sh), so it's POSIX sh.

# HACK_DIR is the path to hack/, which the helpers find the repository
# from. POSIX sh can't tell a sourced file where it is, so a script sets
# it to its own directory before sourcing this; it defaults to "hack" for
# the Makefile's recipes, which run from the repository root.
HACK_DIR="${HACK_DIR:-hack}"

# data_dir_version prints the data directory version this checkout's
# bomify reads and writes: layout.CurrentVersion.
data_dir_version() {
	version_file="$HACK_DIR/../internal/layout/version.go"
	version=$(sed -n 's/^const CurrentVersion = \([0-9][0-9]*\).*/\1/p' "$version_file")
	if [ -z "$version" ]; then
		echo "no CurrentVersion in $version_file" >&2
		return 1
	fi
	echo "$version"
}

# init_data_dir <dir> [version] starts a bomify data directory at dir,
# recording version (default: data_dir_version) in its version.json, so
# files can go in before bomify first runs: bomify refuses a directory
# with content but no version, as one a pre-alpha bomify wrote. A
# directory that already has a version, or content without one, is left
# as it is, for bomify to check.
init_data_dir() {
	dir=$1
	if [ -e "$dir/version.json" ]; then
		return 0
	fi
	if [ -d "$dir" ] && [ -n "$(ls -A "$dir")" ]; then
		return 0
	fi
	version=${2:-$(data_dir_version)} || return 1
	mkdir -p "$dir"
	printf '{\n  "version": %s\n}\n' "$version" > "$dir/version.json"
}
