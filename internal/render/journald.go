package render

import (
	"fmt"
	"strings"

	"github.com/obscure-toolkit/obscure/internal/policy"
)

const journaldPath = "/etc/systemd/journald.conf.d/90-obscure.conf"

func renderJournald(p *policy.Policy) Artifact {
	var b strings.Builder
	b.WriteString(header("journald"))
	b.WriteString("[Journal]\n")
	b.WriteString("Storage=persistent\n")
	fmt.Fprintf(&b, "MaxRetentionSec=%dd\n", p.Privacy.LogRetentionDays)
	fmt.Fprintf(&b, "SystemMaxUse=%dM\n", p.Privacy.LogMaxMB)
	b.WriteString("SystemKeepFree=1G\n")
	b.WriteString("Compress=yes\n")
	b.WriteString("Seal=no\n")
	return Artifact{
		Path: journaldPath, Content: []byte(b.String()), Mode: 0o644,
		Reason:  fmt.Sprintf("keep logs for %d days with a %d MB size cap", p.Privacy.LogRetentionDays, p.Privacy.LogMaxMB),
		Section: "privacy", Kind: KindConfig,
	}
}
