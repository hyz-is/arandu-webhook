package webhook

import (
	"database/sql/driver"
	"fmt"
	"strconv"
)

// Flag is a yes-or-no stored as 0 or 1, which every engine reads the same.
type Flag bool

// Value writes the flag as 0 or 1.
func (f Flag) Value() (driver.Value, error) {
	if f {
		return int64(1), nil
	}
	return int64(0), nil
}

// Scan reads a flag from whatever the engine answers.
func (f *Flag) Scan(value any) error {
	switch v := value.(type) {
	case nil:
		*f = false
	case bool:
		*f = Flag(v)
	case int64:
		*f = v != 0
	case int32:
		*f = v != 0
	case int:
		*f = v != 0
	case float64:
		*f = v != 0
	case []byte:
		return f.Scan(string(v))
	case string:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("webhook: %q is not a yes-or-no", v)
		}
		*f = Flag(b)
	default:
		return fmt.Errorf("webhook: cannot read %T as a yes-or-no", value)
	}
	return nil
}
