package wires

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jampanikomal/tracestate/v2/pkg/detect"
	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

// dockerfileWire parses Dockerfile instructions (with line continuations and
// multi-stage builds) rather than matching raw text.
type dockerfileWire struct{}

type instruction struct {
	cmd  string // upper-case instruction, e.g. "FROM"
	args string
	line int
}

type dockerfileCheck func(r *policy.Rule, file string, ins []instruction) []finding.Finding

var dockerfileChecks = map[string]dockerfileCheck{
	"dockerfile.root_user":          dockerfileRootUser,
	"dockerfile.mutable_base_image": dockerfileMutableBase,
	"dockerfile.remote_add":         dockerfileRemoteAdd,
	"dockerfile.env_secret":         dockerfileEnvSecret,
	"dockerfile.curl_pipe_shell":    dockerfileCurlPipe,
}

func (dockerfileWire) Name() string     { return "dockerfile" }
func (dockerfileWire) Checks() []string { return keys(dockerfileChecks) }

func (dockerfileWire) Scan(_ context.Context, t *scanner.Target, jobs []scanner.Job, _ scanner.Options) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, job := range jobs {
		check := dockerfileChecks[job.Rule.Check]
		err := forEachFile(t, job, func(file string, data []byte) error {
			out = append(out, check(job.Rule, file, parseDockerfile(data))...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func parseDockerfile(data []byte) []instruction {
	var out []instruction
	var cur strings.Builder
	start := 0
	for i, raw := range scanner.Lines(data) {
		line := strings.TrimSpace(raw)
		if cur.Len() == 0 {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			start = i + 1
		} else if strings.HasPrefix(line, "#") {
			continue // comments are allowed inside a continued instruction
		}
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(line)
		text := cur.String()
		cur.Reset()
		cmd, args, _ := strings.Cut(text, " ")
		out = append(out, instruction{cmd: strings.ToUpper(cmd), args: strings.TrimSpace(args), line: start})
	}
	return out
}

// fromImage extracts the image and optional stage alias from FROM arguments.
func fromImage(args string) (image, alias string) {
	fields := strings.Fields(args)
	var rest []string
	for _, f := range fields {
		if !strings.HasPrefix(f, "--") {
			rest = append(rest, f)
		}
	}
	if len(rest) == 0 {
		return "", ""
	}
	image = rest[0]
	if len(rest) >= 3 && strings.EqualFold(rest[1], "as") {
		alias = rest[2]
	}
	return image, alias
}

func dockerfileRootUser(r *policy.Rule, file string, ins []instruction) []finding.Finding {
	var lastFrom, lastUser *instruction
	for i := range ins {
		switch ins[i].cmd {
		case "FROM":
			lastFrom, lastUser = &ins[i], nil
		case "USER":
			lastUser = &ins[i]
		}
	}
	if lastFrom == nil {
		return nil
	}
	image, _ := fromImage(lastFrom.args)
	if strings.Contains(image, "nonroot") {
		return nil
	}
	if lastUser == nil {
		return []finding.Finding{newFinding(r, file, lastFrom.line,
			fmt.Sprintf("final stage (%s) has no USER instruction, so it runs as root", image), "FROM "+lastFrom.args)}
	}
	user := strings.ToLower(strings.Fields(lastUser.args + " ")[0])
	if u, _, _ := strings.Cut(user, ":"); u == "root" || u == "0" {
		return []finding.Finding{newFinding(r, file, lastUser.line,
			"final stage switches to the root user", "USER "+lastUser.args)}
	}
	return nil
}

func dockerfileMutableBase(r *policy.Rule, file string, ins []instruction) []finding.Finding {
	stages := map[string]bool{}
	var out []finding.Finding
	for _, in := range ins {
		if in.cmd != "FROM" {
			continue
		}
		image, alias := fromImage(in.args)
		if alias != "" {
			stages[strings.ToLower(alias)] = true
		}
		if image == "" || image == "scratch" || stages[strings.ToLower(image)] ||
			strings.Contains(image, "$") || strings.Contains(image, "@sha256:") {
			continue
		}
		if _, tag := splitImage(image); tag == "" || tag == "latest" {
			out = append(out, newFinding(r, file, in.line,
				fmt.Sprintf("base image %q is not pinned to a version", image), "FROM "+in.args))
		}
	}
	return out
}

func dockerfileRemoteAdd(r *policy.Rule, file string, ins []instruction) []finding.Finding {
	var out []finding.Finding
	for _, in := range ins {
		if in.cmd != "ADD" || strings.Contains(in.args, "--checksum") {
			continue
		}
		for _, f := range strings.Fields(in.args) {
			if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
				out = append(out, newFinding(r, file, in.line,
					"ADD downloads a remote file without checksum verification", "ADD "+f))
				break
			}
		}
	}
	return out
}

var envPair = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.-]*)=("[^"]*"|'[^']*'|\S+)`)

func dockerfileEnvSecret(r *policy.Rule, file string, ins []instruction) []finding.Finding {
	var out []finding.Finding
	for _, in := range ins {
		if in.cmd != "ENV" && in.cmd != "ARG" {
			continue
		}
		pairs := envPair.FindAllStringSubmatch(in.args, -1)
		if len(pairs) == 0 && in.cmd == "ENV" { // legacy "ENV KEY value"
			if k, v, ok := strings.Cut(in.args, " "); ok {
				pairs = [][]string{{"", k, strings.TrimSpace(v)}}
			}
		}
		for _, p := range pairs {
			key, val := p[1], strings.Trim(p[2], `"'`)
			if !secretName.MatchString(key) || notSecretName.MatchString(key) || isPlaceholder(val) {
				continue
			}
			out = append(out, newFinding(r, file, in.line,
				fmt.Sprintf("%s %s is set to a literal value and will persist in the image history", in.cmd, key),
				in.cmd+" "+key+"="+detect.MaskSecret(val)))
		}
	}
	return out
}

var curlPipe = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|a|da)?sh\b`)

func dockerfileCurlPipe(r *policy.Rule, file string, ins []instruction) []finding.Finding {
	var out []finding.Finding
	for _, in := range ins {
		if in.cmd == "RUN" && curlPipe.MatchString(in.args) {
			out = append(out, newFinding(r, file, in.line,
				"RUN pipes a downloaded script straight into a shell", snippet(curlPipe.FindString(in.args))))
		}
	}
	return out
}
