//go:build !darwin

package store

func excludeFromBackups(string) error { return nil }
