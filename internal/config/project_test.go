package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFromPackageJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Create package.json
	packageJSON := `{
  "name": "my-awesome-project",
  "version": "1.0.0"
}`
	err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	name, err := detectFromPackageJSON(tmpDir)
	if err != nil {
		t.Fatalf("Failed to detect from package.json: %v", err)
	}

	if name != "my-awesome-project" {
		t.Errorf("Expected 'my-awesome-project', got '%s'", name)
	}
}

func TestDetectFromPackageJSONWithScope(t *testing.T) {
	tmpDir := t.TempDir()

	// Create package.json with npm scope
	packageJSON := `{
  "name": "@myorg/my-project",
  "version": "1.0.0"
}`
	err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	name, err := detectFromPackageJSON(tmpDir)
	if err != nil {
		t.Fatalf("Failed to detect from package.json: %v", err)
	}

	// Should remove scope
	if name != "my-project" {
		t.Errorf("Expected 'my-project', got '%s'", name)
	}
}

func TestDetectFromGoMod(t *testing.T) {
	tmpDir := t.TempDir()

	// Create go.mod
	goMod := `module github.com/user/awesome-project

go 1.21`
	err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644)
	if err != nil {
		t.Fatalf("Failed to create go.mod: %v", err)
	}

	name, err := detectFromGoMod(tmpDir)
	if err != nil {
		t.Fatalf("Failed to detect from go.mod: %v", err)
	}

	// Should return full sanitized module path
	if name != "github-com-user-awesome-project" {
		t.Errorf("Expected 'github-com-user-awesome-project', got '%s'", name)
	}
}

func TestDetectFromCargoToml(t *testing.T) {
	tmpDir := t.TempDir()

	// Create Cargo.toml
	cargoToml := `[package]
name = "rust-project"
version = "0.1.0"
edition = "2021"`
	err := os.WriteFile(filepath.Join(tmpDir, "Cargo.toml"), []byte(cargoToml), 0644)
	if err != nil {
		t.Fatalf("Failed to create Cargo.toml: %v", err)
	}

	name, err := detectFromCargoToml(tmpDir)
	if err != nil {
		t.Fatalf("Failed to detect from Cargo.toml: %v", err)
	}

	if name != "rust-project" {
		t.Errorf("Expected 'rust-project', got '%s'", name)
	}
}

func TestDetectFromPyProjectToml(t *testing.T) {
	tmpDir := t.TempDir()

	// Create pyproject.toml
	pyprojectToml := `[project]
name = "python-project"
version = "1.0.0"`
	err := os.WriteFile(filepath.Join(tmpDir, "pyproject.toml"), []byte(pyprojectToml), 0644)
	if err != nil {
		t.Fatalf("Failed to create pyproject.toml: %v", err)
	}

	name, err := detectFromPyProjectToml(tmpDir)
	if err != nil {
		t.Fatalf("Failed to detect from pyproject.toml: %v", err)
	}

	if name != "python-project" {
		t.Errorf("Expected 'python-project', got '%s'", name)
	}
}

func TestDetectFromDirectoryName(t *testing.T) {
	tmpDir := t.TempDir()
	projectDir := filepath.Join(tmpDir, "my-test-project")
	err := os.Mkdir(projectDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	name := detectFromDirectoryName(projectDir)
	if name != "my-test-project" {
		t.Errorf("Expected 'my-test-project', got '%s'", name)
	}
}

func TestDetectProjectNamePriority(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple project files
	packageJSON := `{"name": "from-package-json"}`
	goMod := `module github.com/user/from-go-mod

go 1.21`

	// Test that package.json has highest priority
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644)
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644)

	info, err := DetectProjectName(tmpDir)
	if err != nil {
		t.Fatalf("Failed to detect project name: %v", err)
	}

	if info.Name != "from-package-json" {
		t.Errorf("Expected 'from-package-json', got '%s'", info.Name)
	}

	if info.Source != "package.json" {
		t.Errorf("Expected source 'package.json', got '%s'", info.Source)
	}
}

func TestDetectProjectNameFallback(t *testing.T) {
	tmpDir := t.TempDir()
	projectDir := filepath.Join(tmpDir, "fallback-project")
	err := os.Mkdir(projectDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	// No project files, should fallback to directory name
	info, err := DetectProjectName(projectDir)
	if err != nil {
		t.Fatalf("Failed to detect project name: %v", err)
	}

	if info.Name != "fallback-project" {
		t.Errorf("Expected 'fallback-project', got '%s'", info.Name)
	}

	if info.Source != "directory" {
		t.Errorf("Expected source 'directory', got '%s'", info.Source)
	}
}

func TestSanitizeProjectName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"MyProject", "myproject"},
		{"my-project", "my-project"},
		{"my_project", "my_project"},
		{"my project", "my-project"},
		{"my--project", "my-project"},
		{"@org/project", "org-project"}, // Trims leading/trailing hyphens
		{"project!", "project"},         // Trims trailing hyphens
		{"-project-", "project"},
		{"My Cool Project!", "my-cool-project"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeProjectName(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeProjectName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetProjectName(t *testing.T) {
	tmpDir := t.TempDir()

	// Create package.json
	packageJSON := `{"name": "detected-project"}`
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644)

	// Test with override
	name, source, err := GetProjectName(tmpDir, "override-project")
	if err != nil {
		t.Fatalf("GetProjectName failed: %v", err)
	}

	if name != "override-project" {
		t.Errorf("Expected 'override-project', got '%s'", name)
	}

	if source != "override" {
		t.Errorf("Expected source 'override', got '%s'", source)
	}

	// Test without override (should detect)
	name, source, err = GetProjectName(tmpDir, "")
	if err != nil {
		t.Fatalf("GetProjectName failed: %v", err)
	}

	if name != "detected-project" {
		t.Errorf("Expected 'detected-project', got '%s'", name)
	}

	if source != "package.json" {
		t.Errorf("Expected source 'package.json', got '%s'", source)
	}
}
