package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
)

// fakeWire reports every line containing "BAD" for check fake.bad.
type fakeWire struct{}

func (fakeWire) Name() string     { return "fake" }
func (fakeWire) Checks() []string { return []string{"fake.bad"} }
func (fakeWire) Scan(_ context.Context, t *Target, jobs []Job, _ Options) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, j := range jobs {
		for _, file := range j.Files {
			data, err := t.Read(file)
			if err != nil {
				continue
			}
			for i, line := range Lines(data) {
				if strings.Contains(line, "BAD") {
					f := finding.New(j.Rule, file, i+1)
					f.Message = "bad line"
					f.Evidence = strings.TrimSpace(line)
					out = append(out, f)
				}
			}
		}
	}
	return out, nil
}

func init() { Register(fakeWire{}) }

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestTargetIndexing(t *testing.T) {
	root := tree(t, map[string]string{
		"a.py":                    "x",
		"sub/b.yml":               "y",
		"node_modules/dep/c.js":   "skipped dir",
		".git/config":             "skipped dir",
		"blob.bin":                "\x00\x01\x02",
		"deep/er/still/found.txt": "z",
	})
	tg, err := NewTarget(root)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(tg.Files(), ",")
	if got != "a.py,blob.bin,deep/er/still/found.txt,sub/b.yml" {
		t.Fatalf("files = %s", got)
	}
	if _, err := tg.Read("blob.bin"); !errors.Is(err, ErrBinary) {
		t.Errorf("binary file read err = %v, want ErrBinary", err)
	}
	if m := tg.Match([]string{"**/*.yml", "**/*.py"}, []string{"sub/**"}); strings.Join(m, ",") != "a.py" {
		t.Errorf("Match = %v", m)
	}
	n, err := tg.Exclude([]string{"deep/**"})
	if err != nil || n != 1 || len(tg.Files()) != 3 {
		t.Errorf("Exclude removed %d (err %v), files now %v", n, err, tg.Files())
	}
	if _, err := tg.Exclude([]string{"[bad"}); err == nil {
		t.Error("invalid exclude glob accepted")
	}

	single, err := NewTarget(filepath.Join(root, "sub", "b.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(single.Files(), ",") != "b.yml" {
		t.Errorf("single-file target files = %v", single.Files())
	}
	if _, err := NewTarget(filepath.Join(root, "missing")); err == nil {
		t.Error("missing target accepted")
	}
}

func TestLineHelpers(t *testing.T) {
	data := []byte("one\r\ntwo\nthree")
	if got := Lines(data); len(got) != 3 || got[1] != "two" {
		t.Errorf("Lines = %q", got)
	}
	if LineOf(data, 0) != 1 || LineOf(data, 6) != 2 || LineOf(data, 100) != 3 {
		t.Error("LineOf wrong")
	}
}

func rules(rs ...policy.Rule) *policy.RuleSet { return &policy.RuleSet{Rules: rs, SHA256: "test"} }

func rule(id string, files ...string) policy.Rule {
	return policy.Rule{ID: id, Title: id, Severity: policy.High, Check: "fake.bad", Files: files}
}

func TestRunStatuses(t *testing.T) {
	root := tree(t, map[string]string{"app/main.txt": "fine\nBAD here\n", "app/clean.cfg": "all good"})
	tg, _ := NewTarget(root)
	online := rule("T-ONLINE", "**/*")
	online.Online = true
	res, err := Run(context.Background(), tg, rules(
		rule("T-FAIL", "**/*.txt"),
		rule("T-PASS", "**/*.cfg"),
		rule("T-NA", "**/*.nothing"),
		online,
	), Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]RuleStatus{"T-FAIL": Failed, "T-PASS": Passed, "T-NA": NotApplicable, "T-ONLINE": NotEvaluated}
	for _, rr := range res.Rules {
		if rr.Status != want[rr.RuleID] {
			t.Errorf("%s: status %s, want %s", rr.RuleID, rr.Status, want[rr.RuleID])
		}
	}
	if len(res.Findings) != 1 || res.Findings[0].Line != 2 || res.Findings[0].Fingerprint == "" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if res.Rules[0].Findings != 1 || res.Rules[0].FilesMatched != 1 {
		t.Errorf("T-FAIL counts = %+v", res.Rules[0])
	}

	// With Options.Online the online rule is evaluated too.
	res, err = Run(context.Background(), tg, rules(online), Options{Online: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rules[0].Status != Failed {
		t.Errorf("online rule with --online: %s", res.Rules[0].Status)
	}
}

func TestRunRejectsInvalidRules(t *testing.T) {
	tg, _ := NewTarget(tree(t, map[string]string{"a": "b"}))
	bad := rule("T-1", "**/*")
	bad.Check = "unknown.check"
	if _, err := Run(context.Background(), tg, rules(bad), Options{}); err == nil {
		t.Fatal("expected an error for an unknown check")
	}
}

func TestSuppression(t *testing.T) {
	src := strings.Join([]string{
		"BAD 1 // tracestate:ignore",                           // 1: bare, same line
		"BAD 2 # tracestate:ignore T-A",                        // 2: names this rule
		"BAD 3 # tracestate:ignore T-OTHER",                    // 3: names another rule -> reported
		"# tracestate:ignore T-A false-positive, test fixture", // 4: comment line above 5
		"BAD 5",                      // 5: suppressed by line 4
		"ok = 1 # tracestate:ignore", // 6: trailing directive on a code line...
		"BAD 7",                      // 7: ...does not reach the next line -> reported
		"BAD 8 # tracestate:ignore false-positive", // 8: free-text reason, still bare
	}, "\n")
	tg, _ := NewTarget(tree(t, map[string]string{"f.txt": src}))
	res, err := Run(context.Background(), tg, rules(rule("T-A", "*.txt")), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	for _, f := range res.Findings {
		lines = append(lines, f.Line)
	}
	if len(lines) != 2 || lines[0] != 3 || lines[1] != 7 {
		t.Errorf("reported lines %v, want [3 7]", lines)
	}
	if res.Suppressed != 4 {
		t.Errorf("suppressed = %d, want 4", res.Suppressed)
	}
}

func TestFingerprintIgnoresLineMoves(t *testing.T) {
	r := rule("T-A", "*")
	a := finding.New(&r, "f.txt", 3)
	a.Message, a.Evidence = "bad line", "BAD"
	b := a
	b.Line = 40
	if a.Seal().Fingerprint != b.Seal().Fingerprint {
		t.Error("fingerprint changed when only the line moved")
	}
	b.File = "g.txt"
	if a.Seal().Fingerprint == b.Seal().Fingerprint {
		t.Error("fingerprint ignores the file")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("registering a wire twice should panic")
		}
	}()
	Register(fakeWire{})
}
