package report

import (
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"io"
	texttemplate "text/template"
)

// JSON writes rep as indented JSON.
func JSON(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("report: encode json: %w", err)
	}
	return nil
}

// Markdown writes rep as a Markdown document.
func Markdown(w io.Writer, rep Report) error {
	if err := markdownTemplate.Execute(w, rep); err != nil {
		return fmt.Errorf("report: render markdown: %w", err)
	}
	return nil
}

// HTML writes rep as a self-contained HTML document. All content is escaped by
// html/template, so embedding a captured response body is safe.
func HTML(w io.Writer, rep Report) error {
	if err := htmlTemplate.Execute(w, rep); err != nil {
		return fmt.Errorf("report: render html: %w", err)
	}
	return nil
}

var markdownTemplate = texttemplate.Must(texttemplate.New("md").Parse(`# pinscan report

- **Package:** {{.Scan.Package}}
- **Mode:** {{.Scan.Mode}}{{if .Scan.Transparent}} (transparent){{end}} · window {{.Scan.WindowSeconds}}s{{with .Scan.CATrust}} · research CA trust **{{.}}**{{end}}
- **Schema:** {{.SchemaVersion}}{{with .Run}} · generated {{.StartedAt}}{{end}}
- **Summary:** {{.Summary.Hosts}} hosts · {{.Summary.Interceptable}} interceptable · {{.Summary.NotVerified}} inconclusive (not verified){{if .Summary.Passthrough}} · {{.Summary.Passthrough}} passthrough (not tested){{end}}{{if .Summary.Undetermined}} · {{.Summary.Undetermined}} undetermined (key-pinned){{end}} · {{.Summary.Hardened}} hardened

## Verdicts

| Host | Verdict | Confidence | Interceptable |
|------|---------|------------|:---:|
{{range .Hosts}}| {{.Host}} | {{.Verdict}}{{if .Passthrough}} (passthrough, not tested){{end}} | {{.Confidence}} | {{.InterceptabilityText}} |
{{end}}
"not established" is not a weaker "no": the scan did not determine whether a
trusted-CA attacker defeats the host. For ` + "`key-pinned`" + ` the cloned-issuer wave
did not separate a key check from name validation; re-run until it decides
before recording the host as hardened.

### How each host is pinned

{{range .Hosts}}- **{{.Host}}** — {{.Mechanism}}
{{if .Caveat}}    - ⚠ {{.Caveat}}
{{end}}{{if .Waves}}{{range .Waves}}    - wave {{.Wave}}: {{.Outcome}} ({{.Reason}})
{{end}}{{end}}{{end}}
{{range .Hosts}}{{if .Exchanges}}## {{.Host}} — captured exchanges

{{range .Exchanges}}### {{.Method}} {{.URL}}
{{if .Err}}
> forward error: {{.Err}}
{{else}}
- Status: {{.Status}}
{{if .RespBody}}
` + "```" + `
{{.RespBody}}{{if .RespTruncated}}
…[truncated]{{end}}
` + "```" + `
{{end}}{{end}}
{{end}}{{end}}{{end}}`))

var htmlTemplate = htmltemplate.Must(htmltemplate.New("html").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pinscan report — {{.Scan.Package}}</title>
<style>
:root { --ink:#171717; --mut:#666; --line:#e5e5e5; --bad:#b00020; --ok:#0a7d33; --bg:#fff; --code:#f6f6f7; }
* { box-sizing: border-box; }
body { font: 15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; color:var(--ink); background:var(--bg); margin:0; padding:2rem; }
h1 { font-size:1.4rem; margin:0 0 .25rem; }
h2 { font-size:1.1rem; margin:2rem 0 .5rem; border-top:1px solid var(--line); padding-top:1rem; }
.meta { color:var(--mut); font-size:.9rem; margin-bottom:1.5rem; }
table { border-collapse:collapse; width:100%; margin:1rem 0; font-size:.92rem; }
th,td { text-align:left; padding:.4rem .6rem; border-bottom:1px solid var(--line); }
.badge { font:600 .8rem/1 ui-monospace,monospace; padding:.2rem .45rem; border-radius:.3rem; }
.yes { color:var(--bad); } .no { color:var(--ok); } .not-established { color:#b26a00; }
.note { color:var(--mut); font-size:.85rem; max-width:72ch; }
details { margin:.5rem 0; border:1px solid var(--line); border-radius:.4rem; padding:.4rem .7rem; }
summary { cursor:pointer; font:600 .9rem ui-monospace,monospace; }
pre { background:var(--code); padding:.7rem; border-radius:.4rem; overflow:auto; font-size:.82rem; white-space:pre-wrap; word-break:break-word; }
.err { color:var(--bad); }
.status { color:var(--mut); font-size:.85rem; }
.mech { color:var(--mut); font-size:.8rem; margin-top:.25rem; max-width:52ch; }
.waves { margin-top:.35rem; display:flex; flex-wrap:wrap; gap:.3rem; }
.wave { font:600 .72rem ui-monospace,monospace; background:var(--code); padding:.12rem .4rem; border-radius:.25rem; }
.reason { color:var(--mut); font-weight:400; }
.conf { font:600 .8rem/1 ui-monospace,monospace; }
.conf-low { color:var(--bad); } .conf-medium { color:#b26a00; } .conf-high { color:var(--ok); }
.caveat { color:#b26a00; font-size:.8rem; margin-top:.25rem; max-width:52ch; }
</style>
</head>
<body>
<h1>pinscan report</h1>
<div class="meta">{{.Scan.Package}} · {{.Scan.Mode}}{{if .Scan.Transparent}} (transparent){{end}} · window {{.Scan.WindowSeconds}}s{{with .Scan.CATrust}} · research CA trust {{.}}{{end}} · schema {{.SchemaVersion}}{{with .Run}} · {{.StartedAt}}{{end}}<br>
{{.Summary.Hosts}} hosts · {{.Summary.Interceptable}} interceptable · {{.Summary.NotVerified}} inconclusive (not verified){{if .Summary.Passthrough}} · {{.Summary.Passthrough}} passthrough (not tested){{end}}{{if .Summary.Undetermined}} · {{.Summary.Undetermined}} undetermined (key-pinned){{end}} · {{.Summary.Hardened}} hardened</div>

<table>
<thead><tr><th>Host</th><th>Verdict</th><th>Confidence</th><th>Interceptable</th></tr></thead>
<tbody>
{{range .Hosts}}<tr>
<td>{{.Host}}</td>
<td><span class="badge">{{.Verdict}}</span><div class="mech">{{.Mechanism}}</div>
{{if .Caveat}}<div class="caveat">⚠ {{.Caveat}}</div>{{end}}
{{if .Waves}}<div class="waves">{{range .Waves}}<span class="wave">{{.Wave}}: {{.Outcome}} <span class="reason">({{.Reason}})</span></span>{{end}}</div>{{end}}</td>
<td class="conf conf-{{.Confidence}}">{{.Confidence}}</td>
<td class="{{.Interceptability}}">{{.InterceptabilityText}}</td>
</tr>
{{end}}</tbody>
</table>
<p class="note">"not established" is not a weaker "no": the scan did not determine whether a trusted-CA attacker defeats the host. For key-pinned the cloned-issuer wave did not separate a key check from name validation; re-run until it decides before recording the host as hardened.</p>

{{range .Hosts}}{{if .Exchanges}}<h2>{{.Host}}</h2>
{{range .Exchanges}}<details>
<summary>{{.Method}} {{.URL}} <span class="status">{{if .Err}}error{{else}}→ {{.Status}}{{end}}</span></summary>
{{if .Err}}<p class="err">forward error: {{.Err}}</p>{{else}}{{if .RespBody}}<pre>{{.RespBody}}{{if .RespTruncated}}
…[truncated]{{end}}</pre>{{end}}{{end}}
</details>
{{end}}{{end}}{{end}}
</body>
</html>
`))
