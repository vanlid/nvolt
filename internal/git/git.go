package git

import (
	"fmt"
	"os/exec"
	"strings"
)

// Clone clones a Git repository to the specified path
func Clone(repoURL, targetPath string) error {
	cmd := exec.Command("git", "clone", repoURL, targetPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}

// Pull performs a git pull in the specified directory
func Pull(repoPath string) error {
	cmd := exec.Command("git", "-C", repoPath, "pull", "--rebase")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git pull failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}

// Add stages files for commit in the specified directory
func Add(repoPath string, paths ...string) error {
	args := append([]string{"-C", repoPath, "add"}, paths...)
	cmd := exec.Command("git", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git add failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}

// Commit creates a commit in the specified directory
func Commit(repoPath, message string) error {
	cmd := exec.Command("git", "-C", repoPath, "commit", "-m", message)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if there's nothing to commit
		if strings.Contains(string(output), "nothing to commit") {
			return nil
		}
		return fmt.Errorf("git commit failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}

// Push pushes commits to remote in the specified directory
func Push(repoPath string) error {
	cmd := exec.Command("git", "-C", repoPath, "push")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git push failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}

// Status returns the git status in the specified directory
func Status(repoPath string) (string, error) {
	cmd := exec.Command("git", "-C", repoPath, "status", "--porcelain")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git status failed: %w\nOutput: %s", err, string(output))
	}
	return string(output), nil
}

// IsGitAvailable checks if git is available in PATH
func IsGitAvailable() bool {
	cmd := exec.Command("git", "--version")
	return cmd.Run() == nil
}

// IsGitRepo checks if a directory is a git repository
func IsGitRepo(path string) bool {
	cmd := exec.Command("git", "-C", path, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

// ParseRepoURL parses various repository formats and returns a Git URL
// Supports:
//   - org/repo                           -> git@github.com:org/repo.git
//   - org/repo.git                       -> git@github.com:org/repo.git
//   - git@github.com:org/repo.git        -> git@github.com:org/repo.git (as-is)
//   - https://github.com/org/repo.git    -> https://github.com/org/repo.git (as-is)
//   - git@gitlab.com:org/repo.git        -> git@gitlab.com:org/repo.git (as-is)
func ParseRepoURL(repoSpec string) (string, error) {
	repoSpec = strings.TrimSpace(repoSpec)

	// If it's already a full Git URL (SSH or HTTPS), use as-is
	if strings.HasPrefix(repoSpec, "git@") ||
		strings.HasPrefix(repoSpec, "https://") ||
		strings.HasPrefix(repoSpec, "http://") {
		return repoSpec, nil
	}

	// Parse org/repo or org/repo.git format
	parts := strings.Split(repoSpec, "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid repository format: expected 'org/repo', got '%s'", repoSpec)
	}

	org := strings.TrimSpace(parts[0])
	repo := strings.TrimSpace(parts[1])

	if org == "" || repo == "" {
		return "", fmt.Errorf("invalid repository format: org and repo cannot be empty")
	}

	// Remove .git suffix if present (we'll add it back)
	repo = strings.TrimSuffix(repo, ".git")

	// Default to GitHub SSH
	return fmt.Sprintf("git@github.com:%s/%s.git", org, repo), nil
}

// GetRepoPath extracts org and repo from org/repo string
func GetRepoPath(orgRepo string) (org string, repo string, err error) {
	parts := strings.Split(orgRepo, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repository format: expected 'org/repo', got '%s'", orgRepo)
	}

	org = strings.TrimSpace(parts[0])
	repo = strings.TrimSpace(parts[1])

	if org == "" || repo == "" {
		return "", "", fmt.Errorf("invalid repository format: org and repo cannot be empty")
	}

	return org, repo, nil
}

// HasUncommittedChanges checks if there are uncommitted changes
func HasUncommittedChanges(repoPath string) (bool, error) {
	status, err := Status(repoPath)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(status) != "", nil
}

// HasConflicts checks if there are merge conflicts
func HasConflicts(repoPath string) (bool, error) {
	cmd := exec.Command("git", "-C", repoPath, "diff", "--name-only", "--diff-filter=U")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to check for conflicts: %w", err)
	}
	return strings.TrimSpace(string(output)) != "", nil
}

// GetCurrentBranch returns the current branch name
func GetCurrentBranch(repoPath string) (string, error) {
	cmd := exec.Command("git", "-C", repoPath, "rev-parse", "--abbrev-ref", "HEAD")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get current branch: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// SafePull performs a pull and checks for conflicts
func SafePull(repoPath string) error {
	// Check if there are remote branches (skip pull for empty repos)
	hasRemote, err := HasRemoteBranches(repoPath)
	if err != nil {
		return fmt.Errorf("failed to check remote branches: %w", err)
	}

	// Skip pull for empty repositories
	if !hasRemote {
		return nil
	}

	// Check for uncommitted changes first
	hasChanges, err := HasUncommittedChanges(repoPath)
	if err != nil {
		return fmt.Errorf("failed to check for uncommitted changes: %w", err)
	}
	if hasChanges {
		return fmt.Errorf("cannot pull: you have uncommitted changes. Commit or stash them first")
	}

	// Perform pull
	if err := Pull(repoPath); err != nil {
		return err
	}

	// Check for conflicts
	hasConflicts, err := HasConflicts(repoPath)
	if err != nil {
		return fmt.Errorf("failed to check for conflicts: %w", err)
	}
	if hasConflicts {
		return fmt.Errorf("merge conflicts detected. Please resolve them manually")
	}

	return nil
}

// HasRemoteBranches checks if the repository has any remote branches
func HasRemoteBranches(repoPath string) (bool, error) {
	cmd := exec.Command("git", "-C", repoPath, "ls-remote", "--heads", "origin")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to check remote branches: %w", err)
	}
	return strings.TrimSpace(string(output)) != "", nil
}

// CommitAndPush commits changes and pushes to remote
func CommitAndPush(repoPath, message string, paths ...string) error {
	// Add specified paths first (before pull)
	if len(paths) > 0 {
		if err := Add(repoPath, paths...); err != nil {
			return fmt.Errorf("failed to add files: %w", err)
		}
	}

	// Commit locally first
	if err := Commit(repoPath, message); err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}

	// Check if there are remote branches (skip pull for empty repos)
	hasRemote, err := HasRemoteBranches(repoPath)
	if err != nil {
		return fmt.Errorf("failed to check remote branches: %w", err)
	}

	// Only pull if there are remote branches
	if hasRemote {
		if err := Pull(repoPath); err != nil {
			return fmt.Errorf("failed to pull before push: %w", err)
		}
	}

	// Push to remote
	if !hasRemote {
		// For empty repos (no remote branches), use --set-upstream on first push
		cmd := exec.Command("git", "-C", repoPath, "push", "--set-upstream", "origin", "HEAD")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("git push --set-upstream failed: %w\nOutput: %s", err, string(output))
		}
	} else {
		// Normal push for repos with existing remote branches
		if err := Push(repoPath); err != nil {
			return fmt.Errorf("failed to push: %w", err)
		}
	}

	return nil
}

// FileHistory represents the git history of a file
type FileHistory struct {
	LastModified string // Last commit date
	ModifiedBy   string // Last commit author
}

// GetFileHistory returns the last commit date and author for a file
// Returns empty strings if the file has no git history
func GetFileHistory(repoPath, filePath string) (FileHistory, error) {
	// Check if git is available and this is a git repo
	if !IsGitAvailable() || !IsGitRepo(repoPath) {
		return FileHistory{}, nil
	}

	// Get last commit info for this file
	// Format: "2025-11-08 14:23:45|John Doe"
	cmd := exec.Command("git", "-C", repoPath, "log", "-1", "--format=%ai|%an", "--", filePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// File probably not committed yet
		return FileHistory{}, nil
	}

	result := strings.TrimSpace(string(output))
	if result == "" {
		// No commits for this file
		return FileHistory{}, nil
	}

	// Parse the output
	parts := strings.Split(result, "|")
	if len(parts) != 2 {
		return FileHistory{}, nil
	}

	// Parse the date (format: "2025-11-08 14:23:45 -0500")
	// We'll just take the date and time part
	dateTime := strings.TrimSpace(parts[0])
	author := strings.TrimSpace(parts[1])

	// Simplify the date format (remove timezone)
	if idx := strings.LastIndex(dateTime, " "); idx > 0 {
		// Check if the last part looks like a timezone
		lastPart := dateTime[idx+1:]
		if strings.HasPrefix(lastPart, "+") || strings.HasPrefix(lastPart, "-") {
			dateTime = dateTime[:idx]
		}
	}

	return FileHistory{
		LastModified: dateTime,
		ModifiedBy:   author,
	}, nil
}
