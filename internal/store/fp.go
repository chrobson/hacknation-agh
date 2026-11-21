package store

// Fingerprint module (W1-3) queries: http_obs, detections, tls_legacy and
// signatures. Every function takes a *pgxpool.Pool or a pgx.Tx.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/chrobson/hacknation-agh/internal/httpfp"
	"github.com/chrobson/hacknation-agh/internal/model"
)

// FPQuerier is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type FPQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrSignatureBuiltin is returned when a write would modify a built-in signature.
var ErrSignatureBuiltin = errors.New("built-in signature cannot be modified")

// ErrSignatureNotFound is returned for an unknown signature id.
var ErrSignatureNotFound = errors.New("signature not found")

// SaveHTTPObs upserts the observation of one service. The body is never
// stored, only its SHA-256.
func SaveHTTPObs(ctx context.Context, q FPQuerier, o model.HTTPObs) error {
	headers, err := json.Marshal(fpNonNilMap(o.Headers))
	if err != nil {
		return err
	}
	cookies, err := json.Marshal(fpNonNilSlice(o.Cookies))
	if err != nil {
		return err
	}
	redirects, err := json.Marshal(fpNonNilSlice(o.Redirects))
	if err != nil {
		return err
	}
	var tlsJSON []byte
	if o.TLS != nil {
		if tlsJSON, err = json.Marshal(o.TLS); err != nil {
			return err
		}
	}
	var status, responseMS *int
	if o.Status != 0 {
		status = &o.Status
	}
	if o.ResponseMS > 0 {
		responseMS = &o.ResponseMS
	}
	_, err = q.Exec(ctx, `
INSERT INTO http_obs (service_id, url, status, title, headers, cookies, redirects, tls, favicon_mmh3, body_sha256, response_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (service_id) DO UPDATE SET
    url = EXCLUDED.url, status = EXCLUDED.status, title = EXCLUDED.title,
    headers = EXCLUDED.headers, cookies = EXCLUDED.cookies, redirects = EXCLUDED.redirects,
    tls = EXCLUDED.tls, favicon_mmh3 = EXCLUDED.favicon_mmh3, body_sha256 = EXCLUDED.body_sha256,
    response_ms = EXCLUDED.response_ms`,
		o.ServiceID, o.URL, status, o.Title, headers, cookies, redirects, tlsJSON, o.FaviconMMH3, o.BodySHA256, responseMS)
	return err
}

// GetHTTPObs loads the stored observation of a service (Body is always nil).
func GetHTTPObs(ctx context.Context, q FPQuerier, serviceID int64) (model.HTTPObs, error) {
	o := model.HTTPObs{ServiceID: serviceID}
	var status, responseMS *int
	var headers, cookies, redirects, tlsJSON []byte
	err := q.QueryRow(ctx, `
SELECT url, status, title, headers, cookies, redirects, tls, favicon_mmh3, body_sha256, response_ms
FROM http_obs WHERE service_id = $1`, serviceID).
		Scan(&o.URL, &status, &o.Title, &headers, &cookies, &redirects, &tlsJSON, &o.FaviconMMH3, &o.BodySHA256, &responseMS)
	if err != nil {
		return o, err
	}
	if status != nil {
		o.Status = *status
	}
	if responseMS != nil {
		o.ResponseMS = *responseMS
	}
	if err := json.Unmarshal(headers, &o.Headers); err != nil {
		return o, fmt.Errorf("headers: %w", err)
	}
	if err := json.Unmarshal(cookies, &o.Cookies); err != nil {
		return o, fmt.Errorf("cookies: %w", err)
	}
	if err := json.Unmarshal(redirects, &o.Redirects); err != nil {
		return o, fmt.Errorf("redirects: %w", err)
	}
	if len(tlsJSON) > 0 {
		o.TLS = &model.TLSInfo{}
		if err := json.Unmarshal(tlsJSON, o.TLS); err != nil {
			return o, fmt.Errorf("tls: %w", err)
		}
	}
	return o, nil
}

// ReplaceDetections replaces all detections of a service.
func ReplaceDetections(ctx context.Context, q FPQuerier, serviceID int64, ds []model.Detection) error {
	if _, err := q.Exec(ctx, `DELETE FROM detections WHERE service_id = $1`, serviceID); err != nil {
		return err
	}
	for _, d := range ds {
		ev, err := json.Marshal(fpNonNilMap(d.Evidence))
		if err != nil {
			return err
		}
		if _, err := q.Exec(ctx, `
INSERT INTO detections (service_id, signature_id, name, category, confidence, evidence)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (service_id, signature_id) DO UPDATE SET
    name = EXCLUDED.name, category = EXCLUDED.category,
    confidence = EXCLUDED.confidence, evidence = EXCLUDED.evidence`,
			serviceID, d.SignatureID, d.Name, d.Category, d.Confidence, ev); err != nil {
			return err
		}
	}
	return nil
}

// ListDetections returns the detections of a service ordered by confidence.
func ListDetections(ctx context.Context, q FPQuerier, serviceID int64) ([]model.Detection, error) {
	rows, err := q.Query(ctx, `
SELECT signature_id, name, category, confidence, evidence
FROM detections WHERE service_id = $1 ORDER BY confidence DESC, signature_id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Detection
	for rows.Next() {
		d := model.Detection{ServiceID: serviceID}
		var ev []byte
		if err := rows.Scan(&d.SignatureID, &d.Name, &d.Category, &d.Confidence, &ev); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(ev, &d.Evidence); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SaveLegacyTLS upserts the TLS 1.0/1.1 probe result of a service.
func SaveLegacyTLS(ctx context.Context, q FPQuerier, serviceID int64, r httpfp.LegacyTLS) error {
	_, err := q.Exec(ctx, `
INSERT INTO tls_legacy (service_id, tls10, tls11, tls10_cipher, tls11_cipher, probed_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (service_id) DO UPDATE SET
    tls10 = EXCLUDED.tls10, tls11 = EXCLUDED.tls11,
    tls10_cipher = EXCLUDED.tls10_cipher, tls11_cipher = EXCLUDED.tls11_cipher,
    probed_at = EXCLUDED.probed_at`,
		serviceID, r.TLS10, r.TLS11, r.TLS10Cipher, r.TLS11Cipher)
	return err
}

// GetLegacyTLS loads the TLS 1.0/1.1 probe result (pgx.ErrNoRows if never probed).
func GetLegacyTLS(ctx context.Context, q FPQuerier, serviceID int64) (httpfp.LegacyTLS, error) {
	var r httpfp.LegacyTLS
	err := q.QueryRow(ctx, `SELECT tls10, tls11, tls10_cipher, tls11_cipher FROM tls_legacy WHERE service_id = $1`, serviceID).
		Scan(&r.TLS10, &r.TLS11, &r.TLS10Cipher, &r.TLS11Cipher)
	return r, err
}

// SignatureRow is a row of the signatures table.
type SignatureRow struct {
	ID      string
	Name    string
	YAML    string
	Enabled bool
	Builtin bool
}

// SyncBuiltinSignatures upserts the built-in signatures (rows from sig.Builtin). The enabled flag
// set by users is preserved; a custom signature with the same id is left
// untouched.
func SyncBuiltinSignatures(ctx context.Context, q FPQuerier, sigs []SignatureRow) error {
	for _, s := range sigs {
		if _, err := q.Exec(ctx, `
INSERT INTO signatures (id, name, yaml, enabled, builtin) VALUES ($1, $2, $3, true, true)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, yaml = EXCLUDED.yaml
WHERE signatures.builtin`, s.ID, s.Name, s.YAML); err != nil {
			return fmt.Errorf("signature %s: %w", s.ID, err)
		}
	}
	return nil
}

// ListSignatures returns all signatures ordered by id.
func ListSignatures(ctx context.Context, q FPQuerier) ([]SignatureRow, error) {
	rows, err := q.Query(ctx, `SELECT id, name, yaml, enabled, builtin FROM signatures ORDER BY builtin DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SignatureRow
	for rows.Next() {
		var r SignatureRow
		if err := rows.Scan(&r.ID, &r.Name, &r.YAML, &r.Enabled, &r.Builtin); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetSignature loads one signature row.
func GetSignature(ctx context.Context, q FPQuerier, id string) (SignatureRow, error) {
	var r SignatureRow
	err := q.QueryRow(ctx, `SELECT id, name, yaml, enabled, builtin FROM signatures WHERE id = $1`, id).
		Scan(&r.ID, &r.Name, &r.YAML, &r.Enabled, &r.Builtin)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrSignatureNotFound
	}
	return r, err
}

// CreateCustomSignature inserts a custom signature (the caller validates the
// YAML with sig.Parse first). It fails if the id is already taken.
func CreateCustomSignature(ctx context.Context, q FPQuerier, s SignatureRow) error {
	tag, err := q.Exec(ctx, `
INSERT INTO signatures (id, name, yaml, enabled, builtin) VALUES ($1, $2, $3, true, false)
ON CONFLICT (id) DO NOTHING`, s.ID, s.Name, s.YAML)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("signature id %q already exists", s.ID)
	}
	return nil
}

// UpdateCustomSignature replaces the YAML of a custom signature. The id in
// the YAML must equal id.
func UpdateCustomSignature(ctx context.Context, q FPQuerier, id string, s SignatureRow) error {
	if s.ID != id {
		return fmt.Errorf("signature id cannot change (%q -> %q)", id, s.ID)
	}
	tag, err := q.Exec(ctx, `UPDATE signatures SET name = $2, yaml = $3 WHERE id = $1 AND NOT builtin`, id, s.Name, s.YAML)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fpNotFoundOrBuiltin(ctx, q, id)
	}
	return nil
}

// SetSignatureEnabled toggles a signature (built-in ones included).
func SetSignatureEnabled(ctx context.Context, q FPQuerier, id string, enabled bool) error {
	tag, err := q.Exec(ctx, `UPDATE signatures SET enabled = $2 WHERE id = $1`, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSignatureNotFound
	}
	return nil
}

// DeleteCustomSignature removes a custom signature.
func DeleteCustomSignature(ctx context.Context, q FPQuerier, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM signatures WHERE id = $1 AND NOT builtin`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fpNotFoundOrBuiltin(ctx, q, id)
	}
	return nil
}

func fpNotFoundOrBuiltin(ctx context.Context, q FPQuerier, id string) error {
	r, err := GetSignature(ctx, q, id)
	if err != nil {
		return err
	}
	if r.Builtin {
		return ErrSignatureBuiltin
	}
	return ErrSignatureNotFound
}

func fpNonNilMap[V any](m map[string]V) map[string]V {
	if m == nil {
		return map[string]V{}
	}
	return m
}

func fpNonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
