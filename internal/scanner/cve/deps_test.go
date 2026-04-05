package cve

import (
	"testing"

	"github.com/famclaw/honeybadger/internal/fetch"
)

func TestParseDeps_GoMod(t *testing.T) {
	content := `module example.com/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/crypto v0.14.0
)

require github.com/pkg/errors v0.9.1
`
	repo := &fetch.Repo{
		Files: map[string][]byte{
			"go.mod": []byte(content),
		},
	}

	deps := ParseDeps(repo)
	assertDep(t, deps, "github.com/gin-gonic/gin", "v1.9.1", "Go")
	assertDep(t, deps, "golang.org/x/crypto", "v0.14.0", "Go")
	assertDep(t, deps, "github.com/pkg/errors", "v0.9.1", "Go")

	if len(deps) != 3 {
		t.Errorf("expected 3 deps, got %d: %v", len(deps), deps)
	}
}

func TestParseDeps_PackageLockJSON(t *testing.T) {
	content := `{
		"name": "myapp",
		"lockfileVersion": 3,
		"packages": {
			"": { "version": "1.0.0" },
			"node_modules/lodash": { "version": "4.17.21" },
			"node_modules/express": { "version": "4.18.2" }
		}
	}`

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"package-lock.json": []byte(content),
		},
	}

	deps := ParseDeps(repo)
	assertDep(t, deps, "lodash", "4.17.21", "npm")
	assertDep(t, deps, "express", "4.18.2", "npm")
}

func TestParseDeps_PackageLockJSON_V1(t *testing.T) {
	content := `{
		"name": "myapp",
		"lockfileVersion": 1,
		"dependencies": {
			"lodash": { "version": "4.17.21" },
			"express": { "version": "4.18.2" }
		}
	}`

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"package-lock.json": []byte(content),
		},
	}

	deps := ParseDeps(repo)
	assertDep(t, deps, "lodash", "4.17.21", "npm")
	assertDep(t, deps, "express", "4.18.2", "npm")
}

func TestParseDeps_YarnLock(t *testing.T) {
	content := `# yarn lockfile v1

"lodash@^4.17.21":
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"express@^4.18.0":
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
`

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"yarn.lock": []byte(content),
		},
	}

	deps := ParseDeps(repo)
	assertDep(t, deps, "lodash", "4.17.21", "npm")
	assertDep(t, deps, "express", "4.18.2", "npm")
}

func TestParseDeps_RequirementsTxt(t *testing.T) {
	content := `# Python deps
requests==2.31.0
flask==3.0.0
# comment
numpy==1.25.0
`

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"requirements.txt": []byte(content),
		},
	}

	deps := ParseDeps(repo)
	assertDep(t, deps, "requests", "2.31.0", "PyPI")
	assertDep(t, deps, "flask", "3.0.0", "PyPI")
	assertDep(t, deps, "numpy", "1.25.0", "PyPI")

	if len(deps) != 3 {
		t.Errorf("expected 3 deps, got %d", len(deps))
	}
}

func TestParseDeps_PipfileLock(t *testing.T) {
	content := `{
		"default": {
			"requests": { "version": "==2.31.0" },
			"flask": { "version": "==3.0.0" }
		},
		"develop": {
			"pytest": { "version": "==7.4.0" }
		}
	}`

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"Pipfile.lock": []byte(content),
		},
	}

	deps := ParseDeps(repo)
	assertDep(t, deps, "requests", "2.31.0", "PyPI")
	assertDep(t, deps, "flask", "3.0.0", "PyPI")

	// develop deps should NOT be included
	for _, d := range deps {
		if d.Name == "pytest" {
			t.Error("develop dependencies should not be included")
		}
	}
}

func TestParseDeps_CargoLock(t *testing.T) {
	content := `[[package]]
name = "serde"
version = "1.0.188"

[[package]]
name = "tokio"
version = "1.32.0"
`

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"Cargo.lock": []byte(content),
		},
	}

	deps := ParseDeps(repo)
	assertDep(t, deps, "serde", "1.0.188", "crates.io")
	assertDep(t, deps, "tokio", "1.32.0", "crates.io")
}

func TestParseDeps_GemfileLock(t *testing.T) {
	content := `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)
      actioncable (= 7.0.4)
    rack (2.2.7)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.0)
`

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"Gemfile.lock": []byte(content),
		},
	}

	deps := ParseDeps(repo)
	assertDep(t, deps, "rails", "7.0.4", "RubyGems")
	assertDep(t, deps, "rack", "2.2.7", "RubyGems")
}

func TestParseDeps_PomXML(t *testing.T) {
	content := `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.0.11</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.1.2-jre</version>
    </dependency>
  </dependencies>
</project>`

	repo := &fetch.Repo{
		Files: map[string][]byte{
			"pom.xml": []byte(content),
		},
	}

	deps := ParseDeps(repo)
	assertDep(t, deps, "org.springframework:spring-core", "6.0.11", "Maven")
	assertDep(t, deps, "com.google.guava:guava", "32.1.2-jre", "Maven")
}

func TestParseDeps_EmptyRepo(t *testing.T) {
	repo := &fetch.Repo{
		Files: map[string][]byte{},
	}

	deps := ParseDeps(repo)
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for empty repo, got %d", len(deps))
	}
}

func TestParseDeps_MultipleLockfiles(t *testing.T) {
	repo := &fetch.Repo{
		Files: map[string][]byte{
			"go.mod":           []byte("module test\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n"),
			"requirements.txt": []byte("requests==2.31.0\n"),
		},
	}

	deps := ParseDeps(repo)
	if len(deps) != 2 {
		t.Errorf("expected 2 deps from two lockfiles, got %d: %v", len(deps), deps)
	}
	assertDep(t, deps, "github.com/pkg/errors", "v0.9.1", "Go")
	assertDep(t, deps, "requests", "2.31.0", "PyPI")
}

func assertDep(t *testing.T, deps []Dependency, name, version, ecosystem string) {
	t.Helper()
	for _, d := range deps {
		if d.Name == name && d.Version == version && d.Ecosystem == ecosystem {
			return
		}
	}
	t.Errorf("dependency not found: %s@%s (%s) in %v", name, version, ecosystem, deps)
}
