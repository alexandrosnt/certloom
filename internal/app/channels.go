package app

import (
	"github.com/alexandrosnt/certloom/internal/notify"
	"github.com/alexandrosnt/certloom/internal/store"
)

// ValidateChannel checks a channel's configuration.
func ValidateChannel(c *store.Channel) error { return notify.Validate(c) }
