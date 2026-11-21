package sig

import (
	"context"
	"errors"
	"fmt"

	"github.com/chrobson/hacknation-agh/internal/model"
	"github.com/chrobson/hacknation-agh/internal/store"
)

// DBStore implements Store on top of internal/store.
type DBStore struct {
	Q store.FPQuerier
}

// NewDBStore returns a Store backed by PostgreSQL (*pgxpool.Pool or pgx.Tx).
func NewDBStore(q store.FPQuerier) *DBStore { return &DBStore{Q: q} }

func row(s *Signature) SignatureRow {
	return SignatureRow{ID: s.ID, Name: s.Name, YAML: s.Raw}
}

// List implements Store.
func (d *DBStore) List(ctx context.Context) ([]SignatureRow, error) {
	return store.ListSignatures(ctx, d.Q)
}

// Get implements Store.
func (d *DBStore) Get(ctx context.Context, id string) (SignatureRow, error) {
	return store.GetSignature(ctx, d.Q, id)
}

// Create implements Store.
func (d *DBStore) Create(ctx context.Context, s *Signature) error {
	return store.CreateCustomSignature(ctx, d.Q, row(s))
}

// Update implements Store.
func (d *DBStore) Update(ctx context.Context, id string, s *Signature) error {
	return store.UpdateCustomSignature(ctx, d.Q, id, row(s))
}

// SetEnabled implements Store.
func (d *DBStore) SetEnabled(ctx context.Context, id string, enabled bool) error {
	return store.SetSignatureEnabled(ctx, d.Q, id, enabled)
}

// Delete implements Store.
func (d *DBStore) Delete(ctx context.Context, id string) error {
	return store.DeleteCustomSignature(ctx, d.Q, id)
}

// SyncBuiltin upserts the embedded signatures into the signatures table
// (call once at startup, after migrations).
func SyncBuiltin(ctx context.Context, q store.FPQuerier) error {
	sigs, err := Builtin()
	if err != nil {
		return err
	}
	rows := make([]SignatureRow, 0, len(sigs))
	for _, s := range sigs {
		rows = append(rows, row(s))
	}
	return store.SyncBuiltinSignatures(ctx, q, rows)
}

// LoadEnabled parses every enabled signature from the database. Rows that no
// longer validate are skipped and reported in the joined error, so one bad
// row never disables the others.
func LoadEnabled(ctx context.Context, q store.FPQuerier) ([]*Signature, error) {
	rows, err := store.ListSignatures(ctx, q)
	if err != nil {
		return nil, err
	}
	var out []*Signature
	var errs []error
	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		s, err := Parse([]byte(r.YAML))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.ID, err))
			continue
		}
		out = append(out, s)
	}
	return out, errors.Join(errs...)
}

// Metas returns the classification (CWE, ATT&CK, remediation, references)
// of every signature in the database, enabled or not, keyed by id, so a
// detection from an older run still gets it after its signature was
// disabled. Built-in signatures come from the embedded copy; custom rows
// that no longer parse are skipped.
func Metas(ctx context.Context, q store.FPQuerier) map[string]model.SignatureMeta {
	out := map[string]model.SignatureMeta{}
	if builtin, err := Builtin(); err == nil {
		for _, s := range builtin {
			if m := s.Meta(); m != nil {
				out[s.ID] = *m
			}
		}
	}
	if q == nil {
		return out
	}
	rows, err := store.ListSignatures(ctx, q)
	if err != nil {
		return out
	}
	for _, r := range rows {
		if r.Builtin {
			continue // the embedded copy is current even before SyncBuiltin ran
		}
		s, err := Parse([]byte(r.YAML))
		if err != nil {
			continue
		}
		if m := s.Meta(); m != nil {
			out[s.ID] = *m
		} else {
			delete(out, s.ID)
		}
	}
	return out
}
