package hub

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

// concurrentTransfers is how many of a repository's files Pull downloads,
// or Push uploads, at once.
const concurrentTransfers = 4

// Pull downloads every file of ref's repository at its commit into
// output, each checked against the hash the Hub lists for it, and returns
// their TreeHash.
func Pull(ctx context.Context, hub Client, ref Ref, output string, logger *slog.Logger) (*plugin.Result, error) {
	files, err := hub.ListFiles(ctx, ref)
	if err != nil {
		return nil, err
	}
	logger.Info("downloading", "repository", ref.RepoID(), "revision", ref.Revision, "files", len(files))

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(concurrentTransfers)
	for _, file := range files {
		group.Go(func() error {
			return hub.Download(groupCtx, ref, file, output)
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}

	hash, paths, err := TreeHash(output)
	if err != nil {
		return nil, err
	}
	listed := make([]string, 0, len(files))
	for _, file := range files {
		listed = append(listed, file.Path)
	}
	slices.Sort(listed)
	if !slices.Equal(paths, listed) {
		return nil, fmt.Errorf("%s has %d files on disk after the download, but the Hub lists %d", ref.RepoID(), len(paths), len(listed))
	}
	logger.Info("pulled", "repository", ref.RepoID(), "revision", ref.Revision, "files", len(paths), "hash", hash)

	result := plugin.Result{
		OutputPath: output,
		Message:    fmt.Sprintf("pulled %s@%s (%d files)", ref.RepoID(), ref.Revision, len(paths)),
		Hash:       plugin.NewHash(hash),
	}
	return &result, nil
}

// CheckPull confirms ref's commit exists and its files can be downloaded,
// by listing them and asking for one without downloading it. The hash
// needs every file's content, so it isn't reported.
func CheckPull(ctx context.Context, hub Client, ref Ref) (*plugin.Result, error) {
	files, err := hub.ListFiles(ctx, ref)
	if err != nil {
		return nil, err
	}
	if len(files) > 0 {
		if err := hub.CheckReadable(ctx, ref, files[0]); err != nil {
			return nil, err
		}
	}

	result := plugin.Result{
		OutputPath: ref.Remote() + "/" + ref.Name + "@" + ref.Revision,
		Message:    fmt.Sprintf("%d files", len(files)),
	}
	return &result, nil
}

// Push uploads input, a prior Pull's output, to the main branch of the
// repository named ref.Name in remote's namespace (see ParseRemote), on
// hub, the client for remote's hub, creating it, private, if it doesn't
// exist. Only files main doesn't already hold go up, so pushing again
// after a failure resumes, and pushing the same files twice commits
// nothing. They go up in commits of commitMaxFiles files and
// commitMaxInlineBytes of inline content at most, each on top of the one
// before. Push refuses a repository holding files input doesn't (other
// than the .gitattributes the Hub creates), since the result wouldn't be
// the pulled model. Its commit hash differs from ref's: the files are the
// same, but the commits are new.
func Push(ctx context.Context, hub Client, ref Ref, input, remote string, logger *slog.Logger) (*plugin.Result, error) {
	_, namespace, err := ParseRemote(remote)
	if err != nil {
		return nil, err
	}
	repoID := namespace + "/" + ref.Name
	published := strings.TrimSuffix(strings.TrimPrefix(remote, "https://"), "/") + "/" + ref.Name

	files, err := scanLocalFiles(input)
	if err != nil {
		return nil, err
	}
	if err := hub.CreateRepo(ctx, namespace, ref.Name); err != nil {
		return nil, err
	}
	head, remoteFiles, err := hub.remoteState(ctx, namespace, ref.Name)
	if err != nil {
		return nil, err
	}

	local := map[string]localFile{}
	for _, file := range files {
		local[file.Path] = file
	}
	var extra []string
	var unchanged = map[string]bool{}
	for _, remoteFile := range remoteFiles {
		file, ok := local[remoteFile.Path]
		if !ok && remoteFile.Path != ".gitattributes" {
			extra = append(extra, remoteFile.Path)
		}
		unchanged[remoteFile.Path] = ok && sameContent(file, remoteFile)
	}
	if len(extra) > 0 {
		return nil, fmt.Errorf("%s holds files the pulled model doesn't (%s): push into an empty repository, or one holding this model", repoID, strings.Join(extra, ", "))
	}
	var changed []localFile
	for _, file := range files {
		if !unchanged[file.Path] {
			changed = append(changed, file)
		}
	}

	if err := hub.preupload(ctx, repoID, changed); err != nil {
		return nil, err
	}
	batches := commitBatches(changed)
	if len(batches) == 0 {
		logger.Info("already up to date", "repository", repoID, "commit", head)
		result := plugin.Result{
			OutputPath: published + "@" + head,
			Message:    "already up to date",
		}
		return &result, nil
	}

	var commitURL string
	for index, batch := range batches {
		if err := hub.uploadLFS(ctx, repoID, input, batch); err != nil {
			return nil, err
		}
		message := fmt.Sprintf("Upload %s@%s", ref.RepoID(), ref.Revision)
		if len(batches) > 1 {
			message += fmt.Sprintf(" (%d/%d)", index+1, len(batches))
		}
		head, commitURL, err = hub.commitBatch(ctx, namespace, ref.Name, input, batch, message, head)
		if err != nil {
			return nil, err
		}
		logger.Info("committed", "repository", repoID, "commit", commitURL, "files", len(batch))
	}

	if commitHash.MatchString(head) {
		published += "@" + head
	}
	result := plugin.Result{
		OutputPath: published,
		Message:    fmt.Sprintf("committed %s (%d of %d files changed, in %d commits)", commitURL, len(changed), len(files), len(batches)),
	}
	return &result, nil
}

// CheckPush confirms there's a valid token for remote's hub. Write access
// to the namespace can't be checked without writing, so it isn't.
func CheckPush(ctx context.Context, hub Client, ref Ref, remote string) (*plugin.Result, error) {
	_, namespace, err := ParseRemote(remote)
	if err != nil {
		return nil, err
	}
	name, err := hub.WhoAmI(ctx)
	if err != nil {
		return nil, err
	}

	result := plugin.Result{
		OutputPath: strings.TrimSuffix(strings.TrimPrefix(remote, "https://"), "/") + "/" + ref.Name,
		Message:    fmt.Sprintf("authenticated as %s; write access to %s isn't checked", name, namespace),
	}
	return &result, nil
}
