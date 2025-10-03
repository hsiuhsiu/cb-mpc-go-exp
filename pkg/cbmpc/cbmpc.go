package cbmpc

// LibraryVersion returns the semantic version of the linked cb-mpc library once
// bindings are in place. For now we return a placeholder so the package has a
// concrete API that we can extend alongside the C++ integration.
func LibraryVersion() string {
	return "unversioned"
}
