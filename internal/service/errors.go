package service

import (
	"errors"

	"github.com/uptrace/bun/driver/pgdriver"
)

// isDuplicateKeyError returns true if err is a PostgreSQL unique constraint violation (SQLSTATE 23505).
// Uses errors.As to handle wrapped errors from bun/pgdriver.
func isDuplicateKeyError(err error) bool {
	var pgErr pgdriver.Error
	return errors.As(err, &pgErr) && pgErr.Field('C') == "23505"
}
