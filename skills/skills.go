// Package skills turns the skills a task names into the text of its prompt (spec §5.1). Skills load
// explicitly: a task gets the skills its node names, from the pinned library and the operator's
// private directory, and no others. The sandbox never sees a host-installed skill, because nothing
// loads from the host's own folders.
package skills

import (
	"slices"
	"strings"

	"github.com/ouroboric-dev/havamal"
)

// Record is what run.json keeps about a run's skills: the hash of the whole set, and which skills
// were the operator's own (spec §5.1).
type Record struct {
	Hash    string          `json:"hash"`              // havamal.SetHash of every skill the run may load
	Skills  []string        `json:"skills"`            // their names, sorted
	Private []PrivateRecord `json:"private,omitempty"` // the operator's private skills, with their hashes
}

// PrivateRecord names a private skill and the hash of its files.
type PrivateRecord struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Libraries are the places a task's skills come from.
type Libraries struct {
	Pinned  *havamal.Library // the embedded library, or one under test
	Private *havamal.Library // the operator's directory; may be nil
}

// Load picks the named skills and returns the prompt text for them. No names, no text.
func (l Libraries) Load(names []string) (string, error) {
	loaded, err := havamal.Select(names, l.Pinned, l.Private)
	if err != nil || len(loaded) == 0 {
		return "", err
	}
	var b strings.Builder
	b.WriteString("## Skills\n\nThese skills apply to this task. Follow them.\n")
	for _, s := range loaded {
		b.WriteString("\n### " + s.Name + "\n\n" + strings.TrimSpace(s.Body) + "\n")
	}
	return b.String(), nil
}

// Record returns the record of every skill in names, which a run takes as the union of its agent
// nodes' skills. A name no library holds is an error, so a graph that names a missing skill never
// starts.
func (l Libraries) Record(names []string) (Record, error) {
	unique := slices.Compact(slices.Sorted(slices.Values(names)))
	loaded, err := havamal.Select(unique, l.Pinned, l.Private)
	if err != nil {
		return Record{}, err
	}
	r := Record{Hash: havamal.SetHash(havamal.Entries(loaded)), Skills: unique}
	for _, s := range loaded {
		if s.Private {
			r.Private = append(r.Private, PrivateRecord{Name: s.Name, SHA256: havamal.SetHash([]havamal.Entry{s.Entry})})
		}
	}
	return r, nil
}
