//go:build !darwin

package routes

// Tunnels reports no routes yet away from macOS.
func Tunnels() ([]Route, error) {
	return nil, nil
}
