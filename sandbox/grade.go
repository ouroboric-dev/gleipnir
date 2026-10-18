package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ouroboric-dev/gungnir/schema"
)

// LabelGrader is the label every grader container carries, with the run's id as its value, so ygg doctor
// finds one that a killed ygg left behind. It is not LabelRun: the sandbox of an agent and the container of
// a grader are different things, and a doctor that stops one must not stop the other.
const LabelGrader = "ygg.grader"

// The three places a grader container sees the host, and nothing else (spec §11).
const (
	GradeApp   = "/app"           // the exported project: a copy, read and write
	GradeTests = "/tests"         // the hidden suite: read only
	GradeLogs  = "/logs/verifier" // an empty host folder the suite writes results.json to
)

// ErrGradeTimeout means the suite did not end within the time it was given. The container is removed.
var ErrGradeTimeout = errors.New("the grader timed out")

// GradeSpec is one grading run: a task's image, and the three host folders its container sees.
type GradeSpec struct {
	Run         string        // the run's id: the label's value, and part of the container's name
	Task        string        // the task's id, such as client-gallery-lite
	Environment string        // the task's environment folder, with a Containerfile or a Dockerfile; it is built, never mounted
	App         string        // the project's exported files, as a copy the container may change: Odin throws it away
	Tests       string        // the hidden suite's tests folder, with test.sh; mounted read only
	Logs        string        // an empty host folder; the suite writes results.json to it
	Timeout     time.Duration // the most the container may run
	Memory      string        // the memory limit, such as 4g
	CPUs        int
	Env         map[string]string // the task's verifier.env; NAME in capitals
}

// GradeResult says how a grading run ended. The suite's exit status is not the score: results.json is.
type GradeResult struct {
	Image    string // the image the suite ran in
	ExitCode int    // test.sh's exit status
	Log      string // the end of what the container wrote and the engine said, for the run folder; never for an agent
}

// podman run's own failures: 125 for podman, 126 for a command it could not invoke and 127 for one it
// could not find, which includes a limit the engine could not apply. A suite whose test.sh exits with one
// of them reads the same way, which is a cost worth paying, as with podmanFailed.
const podmanCommandNotFound = 127

// maxGradeLog is how many bytes of the container's output a GradeResult keeps.
const maxGradeLog = 8000

var (
	graderName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	graderRun  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	graderMem  = regexp.MustCompile(`^[1-9][0-9]*[mg]$`)
	graderVar  = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// envContainerfile returns the file of the build context at dir that the image is built from: a
// Containerfile, or else a Dockerfile (a task of the benchmark has one).
func envContainerfile(dir string) (string, error) {
	for _, name := range []string{"Containerfile", "Dockerfile"} {
		if st, err := os.Lstat(filepath.Join(dir, name)); err == nil && st.Mode().IsRegular() {
			return filepath.Join(dir, name), nil
		}
	}
	return "", fmt.Errorf("the environment %s has no Containerfile or Dockerfile (it must be a regular file)", dir)
}

// GraderImage returns the tag of the image built from a task's environment folder: the task's id and a
// hash of every file of the folder, so a changed environment is a new image.
func GraderImage(task, environment string) (string, error) {
	if !graderName.MatchString(task) {
		return "", fmt.Errorf("task %q is not a task id", task)
	}
	if _, err := envContainerfile(environment); err != nil {
		return "", err
	}
	h := sha256.New()
	files, total := 0, int64(0)
	err := filepath.WalkDir(environment, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(environment, path)
		st, err := d.Info()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("the environment holds %s, which is not a regular file; a symlink could lead the build outside it", rel)
		}
		files++
		total += st.Size()
		if files > schema.MaxContextFiles || total > schema.MaxContextBytes {
			return fmt.Errorf("the environment is over its limits (%d files, %d MiB)", schema.MaxContextFiles, schema.MaxContextBytes>>20)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s\x00%v\x00%d\x00", filepath.ToSlash(rel), st.Mode()&0o111 != 0, st.Size())
		h.Write(b)
		return nil
	})
	if err != nil {
		return "", err
	}
	return "localhost/ygg-grader-" + task + ":" + hex.EncodeToString(h.Sum(nil))[:12], nil
}

// BuildGrader builds the image of a task's environment, from bases pinned by digest and its own stages
// only (the rules of BuildStack), and reports false when the image is there already. It is for grading
// alone: the image never holds the hidden suite, which is mounted when the container runs.
func (d *Driver) BuildGrader(ctx context.Context, task, environment string) (ref string, built bool, err error) {
	if ref, err = GraderImage(task, environment); err != nil {
		return "", false, err
	}
	file, err := envContainerfile(environment)
	if err != nil {
		return "", false, err
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", false, err
	}
	bases, _, err := containerfileBases(string(raw))
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", file, err)
	}
	if _, err := d.run(ctx, d.Podman, "image", "exists", ref); err == nil {
		return ref, false, nil
	}
	if err := d.pullAndBuild(ctx, ref, file, environment, "", bases); err != nil {
		return "", false, err
	}
	return ref, true, nil
}

// check refuses a grading run whose folders could not be mounted exactly as the contract says.
func (g GradeSpec) check() error {
	if !graderName.MatchString(g.Task) {
		return fmt.Errorf("task %q is not a task id", g.Task)
	}
	if !graderRun.MatchString(g.Run) {
		return fmt.Errorf("run %q can't name a container", g.Run)
	}
	if g.Timeout <= 0 || g.CPUs < 0 || (g.Memory != "" && !graderMem.MatchString(g.Memory)) {
		return fmt.Errorf("a grading run needs a timeout above zero, no negative cpus and a memory limit such as 4g")
	}
	for _, name := range sortedEnv(g.Env) {
		if !graderVar.MatchString(name) || strings.ContainsAny(g.Env[name], "\n\x00") {
			return fmt.Errorf("env %s can't be passed to the grader", name)
		}
	}
	dirs := []struct{ name, path string }{{"app", g.App}, {"tests", g.Tests}, {"logs", g.Logs}}
	for _, p := range dirs {
		if !filepath.IsAbs(p.path) || filepath.Clean(p.path) != p.path || p.path == "/" || strings.ContainsAny(p.path, ",:\n") {
			return fmt.Errorf("the %s folder %q must be a clean, absolute path without a comma or a colon", p.name, p.path)
		}
		if st, err := os.Stat(p.path); err != nil || !st.IsDir() {
			return fmt.Errorf("the %s folder %s must be a folder", p.name, p.path)
		}
	}
	for i, a := range dirs {
		for _, b := range dirs[i+1:] {
			if a.path == b.path || strings.HasPrefix(a.path, b.path+"/") || strings.HasPrefix(b.path, a.path+"/") {
				return fmt.Errorf("the %s folder and the %s folder must be two folders, neither inside the other", a.name, b.name)
			}
		}
	}
	if st, err := os.Stat(filepath.Join(g.Tests, "test.sh")); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("the tests folder %s has no test.sh", g.Tests)
	}
	if left, err := os.ReadDir(g.Logs); err != nil || len(left) > 0 {
		return fmt.Errorf("the logs folder %s must be empty: a result left in it would pass for this run's", g.Logs)
	}
	return nil
}

// Grade builds the task's image (BuildGrader) and runs the hidden suite in a container of it: no network
// but loopback, /app a read-write copy of the project, /tests the suite read only, /logs/verifier an empty
// host folder, the label ygg.grader=<run>, the memory and CPU limits, and a timeout. It runs
// `bash /tests/test.sh`. The container holds no other mount, and Grade always removes it, on success, on
// failure, on a timeout and on cancellation. A container it can't remove is an error. Like Build it is not
// for an agent's sandbox: no agent ever sees the container or the suite.
func (d *Driver) Grade(ctx context.Context, g GradeSpec) (res GradeResult, err error) {
	if err := g.check(); err != nil {
		return GradeResult{}, err
	}
	var src [3]string
	for i, p := range []string{g.App, g.Tests, g.Logs} {
		if src[i], err = d.cfg.MapPath(p); err != nil {
			return GradeResult{}, err
		}
	}
	ref, _, err := d.BuildGrader(ctx, g.Task, g.Environment)
	if err != nil {
		return GradeResult{}, err
	}
	name := "ygg-grader-" + g.Run + "-" + g.Task
	defer func() {
		// The caller's context may be over: the container is removed all the same.
		rmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if rmErr := d.RemoveGrader(rmCtx, name); rmErr != nil {
			err = errors.Join(err, fmt.Errorf("removing the grader container %s: %w", name, rmErr))
		}
	}()
	args := []string{"run", "--name", name, "--label", LabelGrader + "=" + g.Run, "--network", "none"}
	if g.Memory != "" {
		args = append(args, "--memory", g.Memory)
	}
	if g.CPUs > 0 {
		args = append(args, "--cpus", strconv.Itoa(g.CPUs))
	}
	for _, k := range sortedEnv(g.Env) {
		args = append(args, "--env", k+"="+g.Env[k])
	}
	args = append(args,
		"--mount", "type=bind,src="+src[0]+",dst="+GradeApp,
		"--mount", "type=bind,src="+src[1]+",dst="+GradeTests+",ro=true",
		"--mount", "type=bind,src="+src[2]+",dst="+GradeLogs,
		ref, "bash", GradeTests+"/test.sh")
	runCtx, cancel := context.WithTimeout(ctx, g.Timeout)
	defer cancel()
	out, runErr := d.run(runCtx, d.Podman, args...)
	res = GradeResult{Image: ref}
	if runErr != nil {
		out = append(out, runErr.Error()...)
	}
	res.Log = string(out[max(0, len(out)-maxGradeLog):])
	var ee *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return res, ctx.Err()
	case runCtx.Err() != nil:
		return res, fmt.Errorf("%w after %v", ErrGradeTimeout, g.Timeout)
	case runErr == nil:
		return res, nil
	case errors.As(runErr, &ee) && (ee.ExitCode() < podmanFailed || ee.ExitCode() > podmanCommandNotFound):
		res.ExitCode = ee.ExitCode()
		return res, nil
	}
	return res, fmt.Errorf("podman could not run the grader (exit 125 to 127): %w", runErr)
}

// RemoveGrader removes a grader container, running or not. It is not an error if it is gone.
func (d *Driver) RemoveGrader(ctx context.Context, container string) error {
	_, err := d.run(ctx, d.Podman, "rm", "-f", "--ignore", "--time", "0", container)
	return err
}

// GraderLeftover is a grader container as the engine lists it.
type GraderLeftover struct {
	Run       string
	Container string
	State     string
}

// GraderLeftovers lists every container that carries the grader label, running or not, oldest run first.
func (d *Driver) GraderLeftovers(ctx context.Context) ([]GraderLeftover, error) {
	out, err := d.run(ctx, d.Podman, "ps", "-a", "--filter", "label="+LabelGrader, "--format", "json")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID     string            `json:"Id"`
		State  string            `json:"State"`
		Labels map[string]string `json:"Labels"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("the engine's container list can't be read: %w", err)
	}
	var ls []GraderLeftover
	for _, r := range rows {
		ls = append(ls, GraderLeftover{Run: r.Labels[LabelGrader], Container: r.ID, State: r.State})
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].Run+"\x00"+ls[i].Container < ls[j].Run+"\x00"+ls[j].Container })
	return ls, nil
}
