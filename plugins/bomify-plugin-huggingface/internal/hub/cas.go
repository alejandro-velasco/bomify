package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-huggingface/internal/xet"
)

// errNoXet is a hub without Xet storage, which push then uploads to
// through Git LFS.
var errNoXet = errors.New("the hub has no Xet storage")

// tokenMargin is how long before its expiry a Xet token is renewed.
const tokenMargin = 30 * time.Second

// maxDedupeAnswer bounds a global deduplication answer, a shard.
const maxDedupeAnswer = 64 << 20

// casClient is the Xet storage server for a repository's defaultBranch,
// implementing xet.CAS with a write token from the hub, renewed as it
// expires. Its requests are sent as the Client's are, retried the same
// way, but with that token rather than the hub's.
type casClient struct {
	hub    Client
	repoID string

	mutex   sync.Mutex
	url     string
	token   string
	expires time.Time
}

// newCAS returns repoID's Xet storage, or errNoXet if the hub has none.
func (c Client) newCAS(ctx context.Context, repoID string) (*casClient, error) {
	cas := casClient{
		hub:    c,
		repoID: repoID,
	}
	if _, _, err := cas.connection(ctx); err != nil {
		return nil, err
	}
	return &cas, nil
}

// connection returns the storage server's URL and a token for it,
// asking the hub for a new one when the last is about to expire (see
// https://huggingface.co/docs/xet/auth).
func (c *casClient) connection(ctx context.Context) (string, string, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.token != "" && time.Until(c.expires) > tokenMargin {
		return c.url, c.token, nil
	}

	target := fmt.Sprintf("%s/api/models/%s/xet-write-token/%s", c.hub.Endpoint, c.repoID, defaultBranch)
	response, err := c.hub.get(ctx, http.MethodGet, target)
	var statusErr *StatusError
	if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
		return "", "", errNoXet
	}
	if err != nil {
		return "", "", err
	}
	defer response.Body.Close()
	var answer struct {
		AccessToken string `json:"accessToken"`
		Exp         int64  `json:"exp"`
		CASURL      string `json:"casUrl"`
	}
	if err := json.NewDecoder(response.Body).Decode(&answer); err != nil {
		return "", "", fmt.Errorf("parse the hub's Xet token: %w", err)
	}
	parsed, err := url.Parse(answer.CASURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || answer.AccessToken == "" {
		return "", "", fmt.Errorf("the hub's Xet token has no access token or https:// storage URL (%q)", answer.CASURL)
	}

	c.url = answer.CASURL
	c.token = answer.AccessToken
	c.expires = time.Unix(answer.Exp, 0)
	return c.url, c.token, nil
}

// send sends a request to path on the storage server, with body, if not
// nil, as its content.
func (c *casClient) send(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	base, token, err := c.connection(ctx)
	if err != nil {
		return nil, err
	}
	request := call{
		Method: method,
		URL:    base + path,
		Header: http.Header{"Authorization": {"Bearer " + token}},
	}
	if body != nil {
		request.Body = bytes.NewReader(body)
		request.Size = int64(len(body))
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	return c.hub.send(ctx, request)
}

func (c *casClient) UploadXorb(ctx context.Context, hash xet.Hash, data []byte) error {
	response, err := c.send(ctx, http.MethodPost, "/v1/xorbs/default/"+hash.String(), data)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

func (c *casClient) UploadShard(ctx context.Context, data []byte) error {
	response, err := c.send(ctx, http.MethodPost, "/v1/shards", data)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

func (c *casClient) QueryChunk(ctx context.Context, chunk xet.Hash) ([]byte, error) {
	response, err := c.send(ctx, http.MethodGet, "/v1/chunks/default-merkledb/"+chunk.String(), nil)
	var statusErr *StatusError
	if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, maxDedupeAnswer+1))
	if err != nil {
		return nil, err
	}
	if len(answer) > maxDedupeAnswer {
		return nil, fmt.Errorf("the answer is over %d bytes", maxDedupeAnswer)
	}
	return answer, nil
}
