package skillsafety

import (
	"regexp"
	"strings"

	"github.com/famclaw/honeybadger/internal/fetch"
)

// overridePatterns detects prompt-injection override phrases.
var overridePatterns = []*regexp.Regexp{
	// English
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions`),
	regexp.MustCompile(`(?i)disregard\s+(your\s+)?system\s+prompt`),
	regexp.MustCompile(`(?i)forget\s+everything\s+above`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+a`),
	regexp.MustCompile(`(?i)your\s+new\s+(role|instructions)\s+(is|are)`),
	regexp.MustCompile(`(?i)override\s+safety`),
	regexp.MustCompile(`(?i)bypass\s+(all\s+)?restrictions`),
	regexp.MustCompile(`(?i)do\s+not\s+follow\s+(your\s+)?(original|previous)`),
	// Chinese (Simplified)
	regexp.MustCompile(`忽略(之前的|所有先前的|前面的|上面的)指[令示]`),
	regexp.MustCompile(`无视(系统|之前的)(提示|指令)`),
	regexp.MustCompile(`忘[记掉](上面|之前)的(所有)?(内容|指令)`),
	regexp.MustCompile(`你(现在|从现在开始)(是|扮演)`),
	// Russian
	regexp.MustCompile(`(?i)игнорируй\s+(все\s+)?предыдущие\s+инструкции`),
	regexp.MustCompile(`(?i)забудь\s+(все\s+)?(предыдущие|прошлые)\s+(инструкции|указания)`),
	regexp.MustCompile(`(?i)не\s+следуй\s+(своим\s+)?(оригинальным|предыдущим)\s+инструкциям`),
	regexp.MustCompile(`(?i)ты\s+теперь`),
	// Spanish
	regexp.MustCompile(`(?i)ignora\s+(todas\s+)?las\s+instrucciones\s+(anteriores|previas)`),
	regexp.MustCompile(`(?i)olvida\s+(todo\s+lo\s+anterior|las\s+instrucciones\s+previas)`),
	regexp.MustCompile(`(?i)ahora\s+eres\s+un`),
	regexp.MustCompile(`(?i)tus\s+nuevas\s+instrucciones\s+son`),
	// French
	regexp.MustCompile(`(?i)ignore[rz]?\s+(toutes\s+)?les\s+instructions\s+pr[eé]c[eé]dentes`),
	regexp.MustCompile(`(?i)oublie[rz]?\s+(tout\s+ce\s+qui\s+pr[eé]c[eè]de|les\s+instructions\s+pr[eé]c[eé]dentes)`),
	regexp.MustCompile(`(?i)tu\s+es\s+maintenant`),
	// German
	regexp.MustCompile(`(?i)ignoriere?\s+(alle\s+)?vorherigen?\s+Anweisungen`),
	regexp.MustCompile(`(?i)vergiss\s+(alles\s+)?(vorherige|bisherige)`),
	regexp.MustCompile(`(?i)du\s+bist\s+(jetzt|nun)`),
	// Japanese
	regexp.MustCompile(`(以前の|これまでの|前の)指示を無視`),
	regexp.MustCompile(`(システム)?プロンプトを無視`),
	regexp.MustCompile(`あなたは(今|これから)`),
	// Korean
	regexp.MustCompile(`이전\s*지시[를사항]?\s*무시`),
	regexp.MustCompile(`(시스템\s*)?프롬프트[를을]\s*무시`),
	regexp.MustCompile(`당신은\s*이제`),
	// Arabic
	regexp.MustCompile(`تجاهل\s+(جميع\s+)?التعليمات\s+السابقة`),
	regexp.MustCompile(`انسى?\s+(كل\s+)?(التعليمات|الإرشادات)\s+السابقة`),
	regexp.MustCompile(`أنت\s+الآن`),
	// Portuguese
	regexp.MustCompile(`(?i)ignore\s+(todas\s+)?as\s+instru[çc][õo]es\s+(anteriores|pr[eé]vias)`),
	regexp.MustCompile(`(?i)esque[çc]a\s+(tudo\s+)?o\s+que\s+(foi\s+dito|veio\s+antes)`),
	regexp.MustCompile(`(?i)voc[êe]\s+(agora|agora\s+é)\s+um`),
	// Italian
	regexp.MustCompile(`(?i)ignora\s+(tutte\s+)?le\s+istruzioni\s+precedenti`),
	regexp.MustCompile(`(?i)dimentica\s+(tutto\s+quello\s+che|le\s+istruzioni\s+precedenti)`),
	regexp.MustCompile(`(?i)tu\s+sei\s+(ora|adesso)`),
}

// sensitivePathPatterns detects references to sensitive filesystem paths.
var sensitivePathPatterns = []string{
	"~/.ssh/",
	".env",
	".aws/credentials",
	"wallet.dat",
	"id_rsa",
	"service-account.json",
}

// webhookDomains are known webhook/exfil services.
var webhookDomains = []string{
	"webhook.site",
	"requestbin",
	"pipedream",
	"hookbin",
}

var (
	urlRe  = regexp.MustCompile(`https?://[^\s"'<>` + "`" + `\)]+`)
	execRe = regexp.MustCompile(`curl\s+-.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh`)
)

// Extract reads a skill's body text and all repo files, producing
// structured signals for evaluation.
func Extract(repo *fetch.Repo) Signals {
	var sig Signals
	sig.FileCount = len(repo.Files)

	// Find SKILL.md (case-insensitive).
	var skillContent []byte
	var skillPath string
	for path, content := range repo.Files {
		if strings.EqualFold(path, "SKILL.md") {
			skillContent = content
			skillPath = path
			break
		}
	}

	if skillContent == nil {
		return sig
	}

	raw := string(skillContent)

	// Split on frontmatter delimiter.
	body := raw
	if strings.HasPrefix(strings.TrimSpace(raw), "---") {
		parts := strings.SplitN(raw, "---", 3)
		if len(parts) >= 3 {
			sig.HasFrontmatter = true
			body = parts[2]
		}
	}

	// Scan body for override phrases.
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		for _, pat := range overridePatterns {
			if loc := pat.FindString(line); loc != "" {
				sig.OverridePhrases = append(sig.OverridePhrases, Match{
					Pattern: pat.String(),
					Text:    loc,
					File:    skillPath,
					Line:    i + 1,
				})
			}
		}
	}

	// Scan all text files for sensitive paths, URLs, exec instructions.
	for path, content := range repo.Files {
		s := string(content)
		fileLines := strings.Split(s, "\n")

		for _, sp := range sensitivePathPatterns {
			if strings.Contains(s, sp) {
				sig.SensitivePaths = append(sig.SensitivePaths, sp)
			}
		}

		// External URLs.
		for _, u := range urlRe.FindAllString(s, -1) {
			sig.ExternalURLs = append(sig.ExternalURLs, u)
			for _, wd := range webhookDomains {
				if strings.Contains(u, wd) {
					sig.WebhookURLs = append(sig.WebhookURLs, u)
				}
			}
		}

		// Exec instructions.
		for i, line := range fileLines {
			if loc := execRe.FindString(line); loc != "" {
				sig.ExecInstructions = append(sig.ExecInstructions, Match{
					Pattern: execRe.String(),
					Text:    loc,
					File:    path,
					Line:    i + 1,
				})
			}
		}
	}

	// Unicode analysis on body.
	sig.ZeroWidthChars = CountZeroWidth(body)
	sig.RTLOverrides = CountRTLOverrides(body)
	sig.HTMLComments = ExtractHTMLComments(body)
	sig.HomoglyphWords = DetectHomoglyphs(body)

	// Language detection on body.
	primary, all, unexpected := DetectLanguages(body)
	sig.PrimaryLanguage = primary
	sig.LanguagesDetected = all
	sig.UnexpectedScripts = unexpected

	// Token estimate.
	sig.BodyTokenEstimate = len(body) / 4

	return sig
}
