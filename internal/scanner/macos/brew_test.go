package macos

import "testing"

func checkBrewField(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", label, got, want)
	}
}

func TestParseBrewListOutput(t *testing.T) {
	output := `git 2.43.0
node 20.10.0
python@3.12 3.12.1
wget 1.21.4`

	programs := parseBrewListOutput(output)
	if len(programs) != 4 {
		t.Fatalf("expected 4 programs, got %d", len(programs))
	}

	checkBrewField(t, "Name[0]", programs[0].Name, "git")
	checkBrewField(t, "Version[0]", programs[0].Version, "2.43.0")
	checkBrewField(t, "Name[2]", programs[2].Name, "python@3.12")
	checkBrewField(t, "Version[2]", programs[2].Version, "3.12.1")
}

func TestParseBrewListOutput_MultipleVersions(t *testing.T) {
	// When multiple versions are installed, brew outputs: name v1 v2 v3
	output := `openssl@3 3.2.0 3.1.4`
	programs := parseBrewListOutput(output)
	if len(programs) != 1 {
		t.Fatalf("expected 1 program, got %d", len(programs))
	}
	checkBrewField(t, "Version", programs[0].Version, "3.1.4") // last token
}

func TestParseBrewListOutput_Empty(t *testing.T) {
	programs := parseBrewListOutput("")
	if len(programs) != 0 {
		t.Fatalf("expected 0 programs, got %d", len(programs))
	}
}

func TestParseBrewListOutput_MalformedLines(t *testing.T) {
	output := `git 2.43.0
singlefield
 another

node 20.0.0`
	programs := parseBrewListOutput(output)
	if len(programs) != 2 {
		t.Fatalf("expected 2 programs (skip malformed), got %d", len(programs))
	}
}
