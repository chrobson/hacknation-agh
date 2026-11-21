package dojo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client is a minimal DefectDojo API v2 client (net/http only).
type Client struct {
	BaseURL  string // e.g. http://localhost:8081 (no trailing /api/v2)
	Token    string // API token; obtained with Authenticate when empty
	Username string // used by Authenticate
	Password string // used by Authenticate
	HTTP     *http.Client
}

// PushParams identify where findings land in DefectDojo. Product, product
// type and engagement are created on demand (auto_create_context).
type PushParams struct {
	ProductType string // default "ASI"
	Product     string // default "Attack Surface Intelligence"
	Engagement  string // default "Continuous discovery"
	TestTitle   string // default "ASI Generic Findings"
	TestID      int    // reimport into this test instead of looking it up by name
	ScanDate    time.Time
}

// ImportResult is the subset of the import-scan/reimport-scan response ASI
// records. Statistics is kept verbatim.
type ImportResult struct {
	Endpoint     string          `json:"-"` // "import-scan" or "reimport-scan"
	TestID       int             `json:"test_id"`
	Test         int             `json:"test"`
	EngagementID int             `json:"engagement_id"`
	ProductID    int             `json:"product_id"`
	Statistics   json.RawMessage `json:"statistics,omitempty"`
}

// ID returns the test id regardless of which response field carried it.
func (r ImportResult) ID() int {
	if r.TestID != 0 {
		return r.TestID
	}
	return r.Test
}

// APIError is a non-2xx response from DefectDojo.
type APIError struct {
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("defectdojo %s: HTTP %d: %s", e.Path, e.Status, e.Body)
}

func (p PushParams) withDefaults() PushParams {
	if p.ProductType == "" {
		p.ProductType = "ASI"
	}
	if p.Product == "" {
		p.Product = "Attack Surface Intelligence"
	}
	if p.Engagement == "" {
		p.Engagement = "Continuous discovery"
	}
	if p.TestTitle == "" {
		p.TestTitle = "ASI Generic Findings"
	}
	return p
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 120 * time.Second}
}

func (c *Client) api(path string) (string, error) {
	u, err := url.Parse(strings.TrimRight(c.BaseURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid DefectDojo URL %q", c.BaseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("DefectDojo URL must be http(s)")
	}
	return u.String() + "/api/v2/" + path, nil
}

// Authenticate exchanges Username/Password for an API token via
// /api/v2/api-token-auth/. It is a no-op when Token is already set.
func (c *Client) Authenticate(ctx context.Context) error {
	if c.Token != "" {
		return nil
	}
	if c.Username == "" || c.Password == "" {
		return errors.New("defectdojo: no API token and no username/password")
	}
	u, err := c.api("api-token-auth/")
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"username": c.Username, "password": c.Password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	var out struct {
		Token string `json:"token"`
	}
	if err := c.do(req, "api-token-auth/", &out); err != nil {
		return err
	}
	if out.Token == "" {
		return errors.New("defectdojo: empty token in api-token-auth response")
	}
	c.Token = out.Token
	return nil
}

// ImportScan uploads a Generic Findings file with /api/v2/import-scan/,
// creating product type, product and engagement if missing.
func (c *Client) ImportScan(ctx context.Context, p PushParams, file []byte) (ImportResult, error) {
	return c.upload(ctx, "import-scan/", p, file, false)
}

// ReimportScan uploads a Generic Findings file with /api/v2/reimport-scan/
// and close_old_findings=true, so findings missing from the new file are
// closed in DefectDojo.
func (c *Client) ReimportScan(ctx context.Context, p PushParams, file []byte) (ImportResult, error) {
	return c.upload(ctx, "reimport-scan/", p, file, true)
}

// Push sends a file the idempotent way: reimport into the existing test
// (closing findings that disappeared) and fall back to a first import when
// DefectDojo reports that the test does not exist yet.
func (c *Client) Push(ctx context.Context, p PushParams, file []byte) (ImportResult, error) {
	if err := Validate(file); err != nil {
		return ImportResult{}, fmt.Errorf("refusing to push invalid file: %w", err)
	}
	if err := c.Authenticate(ctx); err != nil {
		return ImportResult{}, err
	}
	r, err := c.ReimportScan(ctx, p, file)
	var apiErr *APIError
	if errors.As(err, &apiErr) && (apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusBadRequest) {
		return c.ImportScan(ctx, p, file)
	}
	return r, err
}

func (c *Client) upload(ctx context.Context, path string, p PushParams, file []byte, reimport bool) (ImportResult, error) {
	if c.Token == "" {
		return ImportResult{}, errors.New("defectdojo: not authenticated")
	}
	u, err := c.api(path)
	if err != nil {
		return ImportResult{}, err
	}
	p = p.withDefaults()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fields := [][2]string{
		{"scan_type", ScanType},
		{"product_type_name", p.ProductType},
		{"product_name", p.Product},
		{"engagement_name", p.Engagement},
		{"test_title", p.TestTitle},
		{"auto_create_context", "true"},
		{"active", "true"},
		{"verified", "false"},
		{"minimum_severity", "Info"},
		{"deduplication_on_engagement", "true"},
		{"close_old_findings", strconv.FormatBool(reimport)},
	}
	if reimport {
		fields = append(fields, [2]string{"do_not_reactivate", "false"})
		if p.TestID > 0 {
			fields = append(fields, [2]string{"test", strconv.Itoa(p.TestID)})
		}
	}
	if !p.ScanDate.IsZero() {
		fields = append(fields, [2]string{"scan_date", p.ScanDate.UTC().Format(dateLayout)})
	}
	for _, f := range fields {
		if err := mw.WriteField(f[0], f[1]); err != nil {
			return ImportResult{}, err
		}
	}
	fw, err := mw.CreateFormFile("file", "asi-findings.json")
	if err != nil {
		return ImportResult{}, err
	}
	if _, err := fw.Write(file); err != nil {
		return ImportResult{}, err
	}
	if err := mw.Close(); err != nil {
		return ImportResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &buf)
	if err != nil {
		return ImportResult{}, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Token "+c.Token)
	var out ImportResult
	if err := c.do(req, path, &out); err != nil {
		return ImportResult{}, err
	}
	out.Endpoint = strings.TrimSuffix(path, "/")
	return out, nil
}

func (c *Client) do(req *http.Request, path string, out any) error {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("defectdojo %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("defectdojo %s: read response: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 512 {
			msg = msg[:512] + "..."
		}
		return &APIError{Path: path, Status: resp.StatusCode, Body: msg}
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("defectdojo %s: decode response: %w", path, err)
	}
	return nil
}
