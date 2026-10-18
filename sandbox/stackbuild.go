package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/ouroboric-dev/gungnir"
	"github.com/ouroboric-dev/gungnir/schema"
)

// BuildStack builds the stack layer of a realm from its build context at dir, up to the Containerfile's
// stage target (its last stage when empty), tagged ref, which is the tag gungnir gives this context and
// stage (schema.StackHash). It reports false when the image is
// there already: the tag is a hash of every file of the context, so an image with it is this image.
//
// The Containerfile may start only from images pinned by digest or from its own stages, and may copy
// only from its own stages: every external base is pulled here, with the isolated registry auth,
// before a build that never pulls. What its RUN lines fetch, at pinned versions, is the realm's to
// pin and the founder's to review. Like Build, it is for ygg sandbox build alone: a run never builds.
func (d *Driver) BuildStack(ctx context.Context, ref, dir, target string) (built bool, err error) {
	if !gungnir.ValidStack(ref) || gungnir.ValidImage(ref) {
		return false, fmt.Errorf("%q is not the tag of a built stack, so it is not built", ref)
	}
	hash, err := schema.StackHash(dir, target)
	if err != nil {
		return false, err
	}
	if !strings.HasSuffix(ref, ":"+hash) {
		return false, fmt.Errorf("the tag %s does not match the build context %s (its hash is %s)", ref, dir, hash)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "Containerfile"))
	if err != nil {
		return false, err
	}
	bases, stages, err := containerfileBases(string(raw))
	if err != nil {
		return false, fmt.Errorf("%s: %w", filepath.Join(dir, "Containerfile"), err)
	}
	if target != "" && !slices.Contains(stages, target) {
		return false, fmt.Errorf("%s has no stage named %q", filepath.Join(dir, "Containerfile"), target)
	}
	if _, err := d.run(ctx, d.Podman, "image", "exists", ref); err == nil {
		return false, nil
	}
	if err := d.pullAndBuild(ctx, ref, filepath.Join(dir, "Containerfile"), dir, target, bases); err != nil {
		return false, err
	}
	return true, nil
}

// pullAndBuild pulls every base with the isolated registry auth, then builds the context at dir from the
// Containerfile file, tagged ref, with a build that never pulls.
func (d *Driver) pullAndBuild(ctx context.Context, ref, file, dir, target string, bases []string) error {
	for _, base := range bases {
		if _, err := d.run(ctx, d.Podman, "pull", "-q", "--authfile", filepath.Join(d.auth, "auth.json"), base); err != nil {
			return err
		}
	}
	args := []string{"build", "--pull=never", "-t", ref, "-f", file}
	if target != "" {
		args = append(args, "--target", target)
	}
	_, err := d.run(ctx, d.Podman, append(args, dir)...)
	return err
}

// containerfileBases returns the external images a Containerfile starts from, once each, and the names of
// its stages, and refuses
// anything that would reach an image nobody pinned: a base without a digest or from an argument, a COPY
// or mount from a stage that does not exist yet or from an image, and ADD, which may fetch a URL.
func containerfileBases(text string) (bases, stages []string, err error) {
	known := func(from string) bool {
		if n, err := strconv.Atoi(from); err == nil {
			return n >= 0 && n < len(stages)
		}
		return slices.Contains(stages, strings.ToLower(from))
	}
	for i, line := range joinContinuations(text) {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "FROM":
			var args []string
			for _, f := range fields[1:] {
				if !strings.HasPrefix(f, "--") {
					args = append(args, f)
				}
			}
			if len(args) == 0 {
				return nil, nil, fmt.Errorf("instruction %d: FROM names no image", i+1)
			}
			img, name := args[0], ""
			if len(args) >= 3 && strings.EqualFold(args[1], "AS") {
				name = strings.ToLower(args[2])
			}
			switch {
			case img == "scratch" || known(img):
			case gungnir.ValidImage(img):
				if !slices.Contains(bases, img) {
					bases = append(bases, img)
				}
			default:
				return nil, nil, fmt.Errorf("instruction %d: FROM %s is not an image pinned by digest or an earlier stage", i+1, img)
			}
			stages = append(stages, name)
		case "COPY", "RUN":
			for _, f := range fields[1:] {
				for _, opt := range strings.Split(strings.TrimPrefix(f, "--mount="), ",") {
					from, ok := strings.CutPrefix(opt, "--from=")
					if !ok {
						from, ok = strings.CutPrefix(opt, "from=")
					}
					if ok && !known(from) {
						return nil, nil, fmt.Errorf("instruction %d: %s from %q, which is not an earlier stage", i+1, strings.ToUpper(fields[0]), from)
					}
				}
			}
		case "ADD":
			return nil, nil, fmt.Errorf("instruction %d: ADD may fetch a file nobody pinned; use COPY", i+1)
		}
	}
	if len(stages) == 0 {
		return nil, nil, fmt.Errorf("no FROM line")
	}
	return bases, stages, nil
}

// joinContinuations joins lines that end with a backslash, as a Containerfile does.
func joinContinuations(text string) []string {
	var out []string
	var cur strings.Builder
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimRight(l, " \t\r")
		if strings.HasPrefix(strings.TrimSpace(l), "#") && cur.Len() == 0 {
			out = append(out, l)
			continue
		}
		if body, ok := strings.CutSuffix(l, "\\"); ok {
			cur.WriteString(body + " ")
			continue
		}
		cur.WriteString(l)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
