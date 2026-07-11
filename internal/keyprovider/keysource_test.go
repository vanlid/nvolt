package keyprovider

import "testing"

func TestLoadKeySourceDefaultsToSoftware(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no machine.json present
	src, err := loadKeySource()
	if err != nil {
		t.Fatal(err)
	}
	if src.Source != "software" {
		t.Fatalf("want software, got %q", src.Source)
	}
}
