// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Command gennotice builds NOTICE from the modules linked into the released
// binaries. Run it via `make notice`; `make notice-check` fails when the
// committed file no longer matches the module graph.
//
// Apache-2.0 section 4(d) obliges a distribution to reproduce the NOTICE text
// of the dependencies it bundles. Nothing about a dependency bump announces
// that a new module brought one along, or that an old one left the build, so
// the committed file can silently stop being correct while every other gate
// stays green. That is what the check exists to catch.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	noticePath = "NOTICE"
	rule       = "--------------------------------------------------------------------------------"
)

// targets are the three released commands. A module linked into any of them
// is bundled in the archives, so all three have to be walked: ozone-login
// pulls in the device-flow dependencies that the proxy never touches.
var targets = []string{"./cmd/proxy", "./cmd/ozone-login", "./cmd/credential-portal"}

// platforms mirrors the goos/goarch matrix in .goreleaser.yaml. Packages are
// selected per platform, so the set of linked modules differs between them:
// prometheus/procfs reaches the linux binaries and not the darwin ones. The
// union is what the archives collectively ship, so the union is what has to
// be attributed. Add a row here when the release matrix gains a platform.
var platforms = []struct{ goos, goarch string }{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
}

// header is reproduced verbatim at the top of the file, above the upstream
// blocks.
const header = `ozone-oidc-proxy
Copyright The ozone-oidc-proxy Authors

This product includes software developed by third parties, distributed under
the Apache License, Version 2.0. The attribution notices of those components
are reproduced below, as required by section 4(d) of that license.
`

// attribution is one upstream NOTICE file, keyed by the module that ships it.
type attribution struct {
	module string
	name   string // file name, for a module shipping more than one
	text   string
}

func main() {
	check := flag.Bool("check", false,
		"report whether NOTICE matches the module graph instead of rewriting it")
	flag.Parse()

	if err := run(*check); err != nil {
		fmt.Fprintln(os.Stderr, "gennotice:", err)
		os.Exit(1)
	}
}

func run(check bool) error {
	mods, err := linkedModules()
	if err != nil {
		return err
	}
	// A module graph this small means `go list` answered but told us nothing
	// useful, which would otherwise render an empty file and call it a pass.
	if len(mods) < 2 {
		return fmt.Errorf("found %d linked modules, expected the dependency tree of %s",
			len(mods), strings.Join(targets, " "))
	}

	attrs, err := collect(mods)
	if err != nil {
		return err
	}
	if len(attrs) == 0 {
		return fmt.Errorf("no NOTICE files found across %d linked modules; "+
			"an empty attribution set is more likely a broken module cache than a dependency tree without one", len(mods))
	}

	want := render(attrs)

	if !check {
		//nolint:gosec // G306: an attribution file shipped to users is world-readable by design.
		if err := os.WriteFile(noticePath, want, 0o644); err != nil {
			return err
		}
		fmt.Printf("%s regenerated: %d attributions from %d linked modules\n",
			noticePath, len(attrs), len(mods))
		for _, a := range attrs {
			fmt.Printf("  %s\n", a.module)
		}
		return nil
	}

	got, err := os.ReadFile(noticePath)
	if err != nil {
		return err
	}
	if bytes.Equal(got, want) {
		fmt.Printf("%s is current: %d attributions from %d linked modules\n",
			noticePath, len(attrs), len(mods))
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s is out of date:\n%s\nRun `make notice` and commit the result.\n",
		noticePath, describeDrift(got, attrs))
	return errors.New("NOTICE does not match the module graph")
}

// linkedModules returns the directories of every module reachable from the
// released binaries, on any release platform, excluding this module itself.
func linkedModules() (map[string]string, error) {
	self, err := selfPath()
	if err != nil {
		return nil, err
	}

	dirs := make(map[string]string)
	for _, p := range platforms {
		args := append([]string{"list", "-deps",
			"-f", "{{if .Module}}{{.Module.Path}}\t{{.Module.Dir}}{{end}}"}, targets...)
		//nolint:gosec // G204: every argument is a constant in this file; the
		// slice exists because there are three commands, not because anything
		// here comes from outside.
		cmd := exec.Command("go", args...)
		cmd.Env = append(os.Environ(), "GOOS="+p.goos, "GOARCH="+p.goarch)
		cmd.Stderr = os.Stderr

		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go list for %s/%s: %w", p.goos, p.goarch, err)
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			path, dir, ok := strings.Cut(strings.TrimSpace(line), "\t")
			if !ok || path == "" || dir == "" || path == self {
				continue
			}
			dirs[path] = dir
		}
	}
	return dirs, nil
}

// selfPath reports this module's own path, so its directory (the repository
// root, which holds the NOTICE being generated) is never scanned as a
// dependency.
func selfPath() (string, error) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Path}}").Output()
	if err != nil {
		return "", fmt.Errorf("resolving the main module: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// collect reads every NOTICE file at the root of a linked module. Upstream
// bytes are copied unchanged apart from trailing newlines, which render
// re-adds, so sub-attributions and accented names in contributor lists
// survive intact.
func collect(mods map[string]string) ([]attribution, error) {
	var attrs []attribution
	for module, dir := range mods {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", module, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasPrefix(strings.ToUpper(e.Name()), "NOTICE") {
				continue
			}
			//nolint:gosec // G304: the path comes from `go list` over this
			// module's own dependency graph, not from user input.
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return nil, fmt.Errorf("reading %s NOTICE: %w", module, err)
			}
			attrs = append(attrs, attribution{
				module: module,
				name:   e.Name(),
				text:   strings.TrimRight(string(b), "\n"),
			})
		}
	}
	sort.Slice(attrs, func(i, j int) bool {
		if attrs[i].module != attrs[j].module {
			return attrs[i].module < attrs[j].module
		}
		return attrs[i].name < attrs[j].name
	})
	return attrs, nil
}

func render(attrs []attribution) []byte {
	var b strings.Builder
	b.WriteString(header)
	for _, a := range attrs {
		fmt.Fprintf(&b, "\n%s\n%s\n\n%s\n", rule, a.module, a.text)
	}
	return []byte(b.String())
}

// describeDrift names the modules the committed file disagrees about, so the
// failure says which dependency changed rather than only that bytes differ.
func describeDrift(got []byte, attrs []attribution) string {
	have := headings(got)
	want := make(map[string]bool, len(attrs))
	for _, a := range attrs {
		want[a.module] = true
	}

	var added, dropped []string
	for m := range want {
		if !have[m] {
			added = append(added, m)
		}
	}
	for m := range have {
		if !want[m] {
			dropped = append(dropped, m)
		}
	}
	sort.Strings(added)
	sort.Strings(dropped)

	var lines []string
	for _, m := range added {
		lines = append(lines, "  + "+m+" ships a NOTICE and is not attributed")
	}
	for _, m := range dropped {
		lines = append(lines, "  - "+m+" is attributed but no longer linked, or no longer ships a NOTICE")
	}
	if len(lines) == 0 {
		return "  the attributed modules match, so the upstream text itself changed"
	}
	return strings.Join(lines, "\n")
}

// headings recovers the attributed module paths from a rendered file: each is
// the line directly after a rule line.
func headings(b []byte) map[string]bool {
	lines := strings.Split(string(b), "\n")
	out := make(map[string]bool)
	for i := 1; i < len(lines); i++ {
		if lines[i-1] == rule && lines[i] != "" {
			out[lines[i]] = true
		}
	}
	return out
}
