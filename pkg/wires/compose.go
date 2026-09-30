package wires

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jampanikomal/tracestate/v2/pkg/detect"
	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

// composeWire understands Docker Compose files structurally (parsed YAML with
// line numbers), so it can reason about services, images, volumes and ports
// instead of grepping for strings.
type composeWire struct{}

type composeService struct {
	name  string
	line  int
	node  *yaml.Node
	image string
}

type composeCheck func(r *policy.Rule, file string, s composeService) []finding.Finding

var composeChecks = map[string]composeCheck{
	"compose.user_root":              composeUserRoot,
	"compose.privileged":             composePrivileged,
	"compose.docker_socket":          composeDockerSocket,
	"compose.host_namespace":         composeHostNamespace,
	"compose.mutable_image_tag":      composeMutableTag,
	"compose.env_secret":             composeEnvSecret,
	"compose.datastore_bind_mount":   composeDatastoreMount,
	"compose.datastore_port_exposed": composeDatastorePort,
	"compose.security_disabled":      composeSecurityDisabled,
}

func (composeWire) Name() string { return "compose" }

func (composeWire) Checks() []string { return keys(composeChecks) }

func (composeWire) Scan(_ context.Context, t *scanner.Target, jobs []scanner.Job, _ scanner.Options) ([]finding.Finding, error) {
	parsed := map[string][]composeService{}
	var out []finding.Finding
	for _, job := range jobs {
		check := composeChecks[job.Rule.Check]
		err := forEachFile(t, job, func(file string, data []byte) error {
			services, ok := parsed[file]
			if !ok {
				services = parseCompose(data)
				parsed[file] = services
			}
			for _, s := range services {
				out = append(out, check(job.Rule, file, s)...)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parseCompose returns the services of a compose file. Files that aren't
// valid YAML or have no services mapping yield nothing.
func parseCompose(data []byte) []composeService {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	_, services := mapGet(doc.Content[0], "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil
	}
	var out []composeService
	for i := 0; i+1 < len(services.Content); i += 2 {
		k, v := services.Content[i], services.Content[i+1]
		if v.Kind != yaml.MappingNode {
			continue
		}
		s := composeService{name: k.Value, line: k.Line, node: v}
		if _, img := mapGet(v, "image"); img != nil {
			s.image = img.Value
		}
		out = append(out, s)
	}
	return out
}

func mapGet(m *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

func composeUserRoot(r *policy.Rule, file string, s composeService) []finding.Finding {
	_, v := mapGet(s.node, "user")
	if v == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(v.Value)) {
	case "root", "0", "0:0", "root:root", "root:0", "0:root":
		return []finding.Finding{newFinding(r, file, v.Line,
			fmt.Sprintf("service %q explicitly runs as %q", s.name, v.Value), "user: "+v.Value)}
	}
	return nil
}

func composePrivileged(r *policy.Rule, file string, s composeService) []finding.Finding {
	_, v := mapGet(s.node, "privileged")
	if v != nil && strings.EqualFold(v.Value, "true") {
		return []finding.Finding{newFinding(r, file, v.Line,
			fmt.Sprintf("service %q runs privileged", s.name), "privileged: true")}
	}
	return nil
}

// volume is one entry of a service's volumes list in either syntax.
type volume struct {
	source, target string
	line           int
}

func volumes(s composeService) []volume {
	_, v := mapGet(s.node, "volumes")
	if v == nil || v.Kind != yaml.SequenceNode {
		return nil
	}
	var out []volume
	for _, item := range v.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			parts := splitVolume(item.Value)
			vol := volume{source: parts[0], line: item.Line}
			if len(parts) > 1 {
				vol.target = parts[1]
			}
			out = append(out, vol)
		case yaml.MappingNode:
			_, src := mapGet(item, "source")
			_, dst := mapGet(item, "target")
			vol := volume{line: item.Line}
			if src != nil {
				vol.source = src.Value
			}
			if dst != nil {
				vol.target = dst.Value
			}
			out = append(out, vol)
		}
	}
	return out
}

// splitVolume splits "src:dst[:mode]" while tolerating a Windows drive
// letter in the source ("C:\data:/var/lib/mysql").
func splitVolume(spec string) []string {
	if len(spec) > 2 && spec[1] == ':' && (spec[2] == '\\' || spec[2] == '/') {
		rest := strings.SplitN(spec[2:], ":", 3)
		rest[0] = spec[:2] + rest[0]
		return rest
	}
	return strings.SplitN(spec, ":", 3)
}

func isHostPath(src string) bool {
	return strings.HasPrefix(src, ".") || strings.HasPrefix(src, "/") || strings.HasPrefix(src, "~") ||
		(len(src) > 2 && src[1] == ':')
}

func composeDockerSocket(r *policy.Rule, file string, s composeService) []finding.Finding {
	var out []finding.Finding
	for _, vol := range volumes(s) {
		if strings.Contains(vol.source, "docker.sock") {
			out = append(out, newFinding(r, file, vol.line,
				fmt.Sprintf("service %q mounts the Docker socket (%s)", s.name, vol.source),
				vol.source+":"+vol.target))
		}
	}
	return out
}

func composeHostNamespace(r *policy.Rule, file string, s composeService) []finding.Finding {
	var out []finding.Finding
	for _, key := range []string{"network_mode", "pid", "ipc", "userns_mode", "uts"} {
		_, v := mapGet(s.node, key)
		if v != nil && strings.EqualFold(v.Value, "host") {
			out = append(out, newFinding(r, file, v.Line,
				fmt.Sprintf("service %q shares the host %s namespace", s.name, strings.TrimSuffix(key, "_mode")),
				key+": host"))
		}
	}
	return out
}

func composeMutableTag(r *policy.Rule, file string, s composeService) []finding.Finding {
	if s.image == "" || strings.Contains(s.image, "${") || strings.Contains(s.image, "@sha256:") {
		return nil
	}
	if _, build := mapGet(s.node, "build"); build != nil {
		return nil // image names the locally built result, nothing is pulled
	}
	_, v := mapGet(s.node, "image")
	name, tag := splitImage(s.image)
	if tag == "" || tag == "latest" {
		msg := fmt.Sprintf("service %q uses image %q with no version tag", s.name, name)
		if tag == "latest" {
			msg = fmt.Sprintf("service %q uses the mutable tag %q", s.name, s.image)
		}
		return []finding.Finding{newFinding(r, file, v.Line, msg, "image: "+s.image)}
	}
	return nil
}

// splitImage splits "registry:5000/org/name:tag[@digest]" into name and tag,
// taking care not to mistake a registry port or a digest for a tag.
func splitImage(ref string) (name, tag string) {
	if at := strings.IndexByte(ref, '@'); at >= 0 { // drop a digest: name[:tag]@sha256:...
		ref = ref[:at]
	}
	slash := strings.LastIndexByte(ref, '/')
	colon := strings.LastIndexByte(ref, ':')
	if colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	return ref, ""
}

// environment returns a service's environment entries in either list
// ("KEY=value") or mapping (KEY: value) form.
func environment(s composeService) []envVar {
	_, v := mapGet(s.node, "environment")
	if v == nil {
		return nil
	}
	var out []envVar
	switch v.Kind {
	case yaml.SequenceNode:
		for _, item := range v.Content {
			k, val, _ := strings.Cut(item.Value, "=")
			out = append(out, envVar{key: strings.TrimSpace(k), value: strings.TrimSpace(val), line: item.Line})
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(v.Content); i += 2 {
			out = append(out, envVar{key: v.Content[i].Value, value: v.Content[i+1].Value, line: v.Content[i].Line})
		}
	}
	return out
}

type envVar struct {
	key, value string
	line       int
}

func composeEnvSecret(r *policy.Rule, file string, s composeService) []finding.Finding {
	var out []finding.Finding
	for _, e := range environment(s) {
		if !secretName.MatchString(e.key) || notSecretName.MatchString(e.key) || isPlaceholder(e.value) {
			continue
		}
		out = append(out, newFinding(r, file, e.line,
			fmt.Sprintf("service %q sets %s to a literal value", s.name, e.key),
			e.key+"="+detect.MaskSecret(e.value)))
	}
	return out
}

// datastores maps the final image-name component of common databases and
// search engines to a display name.
var datastores = map[string]string{
	"postgres": "PostgreSQL", "postgresql": "PostgreSQL", "postgis": "PostgreSQL",
	"mysql": "MySQL", "mariadb": "MariaDB", "mongo": "MongoDB", "mongodb": "MongoDB",
	"redis": "Redis", "valkey": "Valkey", "elasticsearch": "Elasticsearch", "opensearch": "OpenSearch",
	"cassandra": "Cassandra", "couchdb": "CouchDB", "influxdb": "InfluxDB", "neo4j": "Neo4j",
	"clickhouse-server": "ClickHouse", "memcached": "Memcached",
}

func datastoreName(image string) string {
	name, _ := splitImage(image)
	base := name[strings.LastIndexByte(name, '/')+1:]
	if base == "server" { // mcr.microsoft.com/mssql/server
		if strings.Contains(name, "mssql") {
			return "SQL Server"
		}
		return ""
	}
	return datastores[base]
}

func composeDatastoreMount(r *policy.Rule, file string, s composeService) []finding.Finding {
	db := datastoreName(s.image)
	if db == "" {
		return nil
	}
	var out []finding.Finding
	for _, vol := range volumes(s) {
		if vol.target == "" || !isHostPath(vol.source) || strings.Contains(vol.source, "docker.sock") {
			continue
		}
		out = append(out, newFinding(r, file, vol.line,
			fmt.Sprintf("%s data for service %q is stored in host directory %s; encryption at rest isn't evident", db, s.name, vol.source),
			vol.source+":"+vol.target))
	}
	return out
}

func composeDatastorePort(r *policy.Rule, file string, s composeService) []finding.Finding {
	db := datastoreName(s.image)
	if db == "" {
		return nil
	}
	_, ports := mapGet(s.node, "ports")
	if ports == nil || ports.Kind != yaml.SequenceNode {
		return nil
	}
	var out []finding.Finding
	for _, p := range ports.Content {
		hostIP, spec := "", p.Value
		if p.Kind == yaml.MappingNode {
			_, ip := mapGet(p, "host_ip")
			_, pub := mapGet(p, "published")
			if ip != nil {
				hostIP = ip.Value
			}
			if pub == nil {
				continue
			}
			spec = pub.Value
		} else if strings.HasPrefix(p.Value, "[") { // "[::1]:5432:5432"
			if end := strings.IndexByte(p.Value, ']'); end > 0 {
				hostIP = p.Value[1:end]
			}
		} else if parts := strings.Split(p.Value, ":"); len(parts) == 3 {
			hostIP = parts[0]
		}
		if hostIP == "127.0.0.1" || hostIP == "localhost" || hostIP == "::1" || hostIP == "[::1]" {
			continue
		}
		out = append(out, newFinding(r, file, p.Line,
			fmt.Sprintf("%s service %q publishes port %s on every host interface", db, s.name, spec),
			"ports: "+spec))
	}
	return out
}

func composeSecurityDisabled(r *policy.Rule, file string, s composeService) []finding.Finding {
	var out []finding.Finding
	for _, e := range environment(s) {
		k, v := strings.ToLower(e.key), strings.ToLower(e.value)
		insecure := (k == "xpack.security.enabled" && v == "false") ||
			(k == "plugins.security.disabled" && v == "true") ||
			(k == "disable_security_plugin" && v == "true") ||
			(strings.HasSuffix(k, "allow_empty_password") && (v == "yes" || v == "true" || v == "1")) ||
			(k == "postgres_host_auth_method" && v == "trust")
		if insecure {
			out = append(out, newFinding(r, file, e.line,
				fmt.Sprintf("service %q disables authentication/security with %s=%s", s.name, e.key, e.value),
				e.key+"="+e.value))
		}
	}
	return out
}
