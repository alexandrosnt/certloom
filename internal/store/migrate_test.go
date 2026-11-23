package store_test

import (
	"sync"
	"testing"

	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/store/storetest"
	"github.com/jackc/pgx/v5"
)

// Replicas upgraded together run migrate at the same time. All runs must
// succeed and every migration must be applied exactly once.
func TestMigrateConcurrently(t *testing.T) {
	url := storetest.Empty(t)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Go(func() { errs[i] = store.Migrate(ctx, url) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("migrate %d: %v", i, err)
		}
	}
	c, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	var dup int
	err = c.QueryRow(ctx, `SELECT count(*) FROM (SELECT version_id FROM goose_db_version
		WHERE version_id > 0 GROUP BY version_id HAVING count(*) > 1) d`).Scan(&dup)
	if err != nil {
		t.Fatal(err)
	}
	if dup > 0 {
		t.Fatalf("%d migrations recorded more than once", dup)
	}
}
