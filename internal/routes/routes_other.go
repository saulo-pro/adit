//go:build !darwin

package routes

// Tunnels reports no routes yet away from macOS.
func Tunnels() ([]Route, error) {
	return nil, nil
}

// All reports no routes yet away from macOS.
func All() ([]Route, error) {
	return nil, nil
}
