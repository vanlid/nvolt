package vault

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testData := []byte("test data")

	err := WriteFileAtomic(testFile, testData, FilePerm)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// Verify file exists
	if !FileExists(testFile) {
		t.Error("File doesn't exist after write")
	}

	// Read and verify content
	data, err := ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("Expected %s, got %s", testData, data)
	}

	// Verify no temp file remains
	tmpFile := testFile + ".tmp"
	if FileExists(tmpFile) {
		t.Error("Temporary file should have been removed")
	}
}

func TestPermsEqual(t *testing.T) {
	cases := []struct {
		name             string
		actual, expected fs.FileMode
		goos             string
		want             bool
	}{
		// Unix: exact match required.
		{"unix exact match", 0o644, 0o644, "linux", true},
		{"unix mismatch rejected", 0o666, 0o644, "linux", false},
		{"unix private key exact", 0o600, 0o600, "darwin", true},
		// Windows: a writable file always reports 0666, so 0644/0600 expectations
		// must both be satisfied by an on-disk 0666 (the enroll-crash scenario).
		{"windows writable matches 0644", 0o666, 0o644, "windows", true},
		{"windows writable matches 0600", 0o666, 0o600, "windows", true},
		// Windows: read-only expectation must still be honored (read-only bit differs).
		{"windows readonly not writable", 0o666, 0o444, "windows", false},
		{"windows readonly matches readonly", 0o444, 0o444, "windows", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := permsEqual(c.actual, c.expected, c.goos); got != c.want {
				t.Errorf("permsEqual(%o, %o, %q) = %v, want %v", c.actual, c.expected, c.goos, got, c.want)
			}
		})
	}
}

func TestWriteFileAtomicCreatesParentDir(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "subdir", "nested", "test.txt")
	testData := []byte("test data")

	err := WriteFileAtomic(testFile, testData, FilePerm)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	if !FileExists(testFile) {
		t.Error("File doesn't exist after write")
	}
}

func TestReadFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testData := []byte("test data")

	err := os.WriteFile(testFile, testData, FilePerm)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	data, err := ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("Expected %s, got %s", testData, data)
	}
}

func TestReadFileNotExist(t *testing.T) {
	_, err := ReadFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestDeleteFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	err := os.WriteFile(testFile, []byte("test"), FilePerm)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	err = DeleteFile(testFile)
	if err != nil {
		t.Fatalf("Failed to delete file: %v", err)
	}

	if FileExists(testFile) {
		t.Error("File still exists after delete")
	}
}

func TestDeleteFileNotExist(t *testing.T) {
	err := DeleteFile("/nonexistent/file.txt")
	if err != nil {
		t.Errorf("Delete nonexistent file should not error: %v", err)
	}
}

func TestFileExists(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	// File doesn't exist
	if FileExists(testFile) {
		t.Error("File should not exist")
	}

	// Create file
	err := os.WriteFile(testFile, []byte("test"), FilePerm)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// File exists
	if !FileExists(testFile) {
		t.Error("File should exist")
	}
}

func TestListFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	files := []string{"file1.txt", "file2.txt", "file3.txt"}
	for _, f := range files {
		path := filepath.Join(tmpDir, f)
		err := os.WriteFile(path, []byte("test"), FilePerm)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Create a subdirectory (should not be listed)
	subdir := filepath.Join(tmpDir, "subdir")
	err := os.Mkdir(subdir, DirPerm)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// List files
	listedFiles, err := ListFiles(tmpDir)
	if err != nil {
		t.Fatalf("Failed to list files: %v", err)
	}

	if len(listedFiles) != len(files) {
		t.Errorf("Expected %d files, got %d", len(files), len(listedFiles))
	}
}

func TestListFilesEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	files, err := ListFiles(tmpDir)
	if err != nil {
		t.Fatalf("Failed to list files: %v", err)
	}

	if len(files) != 0 {
		t.Errorf("Expected 0 files, got %d", len(files))
	}
}

func TestListFilesNotExist(t *testing.T) {
	files, err := ListFiles("/nonexistent/directory")
	if err != nil {
		t.Fatalf("ListFiles should not error for nonexistent directory: %v", err)
	}

	if len(files) != 0 {
		t.Errorf("Expected 0 files, got %d", len(files))
	}
}

func TestListDirs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test directories
	dirs := []string{"dir1", "dir2", "dir3"}
	for _, d := range dirs {
		path := filepath.Join(tmpDir, d)
		err := os.Mkdir(path, DirPerm)
		if err != nil {
			t.Fatalf("Failed to create test directory: %v", err)
		}
	}

	// Create a file (should not be listed)
	file := filepath.Join(tmpDir, "file.txt")
	err := os.WriteFile(file, []byte("test"), FilePerm)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// List directories
	listedDirs, err := ListDirs(tmpDir)
	if err != nil {
		t.Fatalf("Failed to list directories: %v", err)
	}

	if len(listedDirs) != len(dirs) {
		t.Errorf("Expected %d directories, got %d", len(dirs), len(listedDirs))
	}
}

func TestInitializeVaultDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, ".nvolt")

	err := InitializeVaultDirectory(vaultPath)
	if err != nil {
		t.Fatalf("Failed to initialize vault directory: %v", err)
	}

	// Verify all directories were created
	paths := GetVaultPaths(vaultPath, "")
	requiredDirs := []string{
		paths.Root,
		paths.Secrets,
		paths.WrappedKeys,
		paths.Machines,
	}

	for _, dir := range requiredDirs {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("Directory %s doesn't exist: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", dir)
		}
	}
}

func TestEnsureSecretsDir(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, ".nvolt")

	err := InitializeVaultDirectory(vaultPath)
	if err != nil {
		t.Fatalf("Failed to initialize vault directory: %v", err)
	}

	paths := GetVaultPaths(vaultPath, "")
	environment := "production"

	err = EnsureSecretsDir(paths, environment)
	if err != nil {
		t.Fatalf("Failed to ensure secrets directory: %v", err)
	}

	secretsPath := paths.GetSecretsPath(environment)
	info, err := os.Stat(secretsPath)
	if err != nil {
		t.Errorf("Secrets directory doesn't exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("Secrets path is not a directory")
	}
}

func TestValidateVaultStructure(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, ".nvolt")

	// Should fail before initialization
	err := ValidateVaultStructure(vaultPath)
	if err == nil {
		t.Error("Expected error for uninitialized vault")
	}

	// Initialize vault
	err = InitializeVaultDirectory(vaultPath)
	if err != nil {
		t.Fatalf("Failed to initialize vault directory: %v", err)
	}

	// Should succeed after initialization
	err = ValidateVaultStructure(vaultPath)
	if err != nil {
		t.Errorf("Validation failed for initialized vault: %v", err)
	}
}

func TestIsVaultInitialized(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, ".nvolt")

	// Should be false before initialization
	if IsVaultInitialized(vaultPath) {
		t.Error("Vault should not be initialized")
	}

	// Create vault directory
	err := InitializeVaultDirectory(vaultPath)
	if err != nil {
		t.Fatalf("Failed to initialize vault directory: %v", err)
	}

	// Should be true after initialization
	if !IsVaultInitialized(vaultPath) {
		t.Error("Vault should be initialized")
	}
}
