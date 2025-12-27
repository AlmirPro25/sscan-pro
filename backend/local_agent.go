package main

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// FileInfo represents a file or directory
type FileInfo struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	IsDir    bool   `json:"is_dir"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
	Children int    `json:"children,omitempty"` // Number of children if directory
}

// BrowseResponse represents the response for directory browsing
type BrowseResponse struct {
	CurrentPath string     `json:"current_path"`
	ParentPath  string     `json:"parent_path"`
	Items       []FileInfo `json:"items"`
	Drives      []string   `json:"drives,omitempty"` // Windows drives
}

// handleBrowseDirectory handles directory browsing requests
func handleBrowseDirectory(c *gin.Context) {
	path := c.Query("path")
	
	// If no path provided, return drives (Windows) or root (Unix)
	if path == "" {
		drives := getAvailableDrives()
		c.JSON(http.StatusOK, BrowseResponse{
			CurrentPath: "",
			ParentPath:  "",
			Items:       []FileInfo{},
			Drives:      drives,
		})
		return
	}

	// Validate path exists
	info, err := os.Stat(path)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path does not exist: " + path})
		return
	}

	if !info.IsDir() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path is not a directory"})
		return
	}

	// Read directory contents
	entries, err := os.ReadDir(path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cannot read directory: " + err.Error()})
		return
	}

	var items []FileInfo
	
	for _, entry := range entries {
		// Skip hidden files/folders (starting with .)
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		
		// Skip common non-project folders
		skipFolders := []string{"node_modules", "__pycache__", ".git", "vendor", "dist", "build", ".next", ".nuxt", "venv", ".venv"}
		shouldSkip := false
		for _, skip := range skipFolders {
			if entry.Name() == skip {
				shouldSkip = true
				break
			}
		}
		
		fullPath := filepath.Join(path, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		item := FileInfo{
			Name:     entry.Name(),
			Path:     fullPath,
			IsDir:    entry.IsDir(),
			Size:     info.Size(),
			Modified: info.ModTime().Format("2006-01-02 15:04"),
		}

		// Count children for directories (only if not skipped)
		if entry.IsDir() && !shouldSkip {
			if subEntries, err := os.ReadDir(fullPath); err == nil {
				item.Children = len(subEntries)
			}
		}
		
		// Mark skipped folders but still show them
		if shouldSkip {
			item.Children = -1 // Indicator that it's skipped
		}

		items = append(items, item)
	}

	// Sort: directories first, then by name
	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	// Get parent path
	parentPath := filepath.Dir(path)
	if parentPath == path {
		parentPath = "" // Root reached
	}

	c.JSON(http.StatusOK, BrowseResponse{
		CurrentPath: path,
		ParentPath:  parentPath,
		Items:       items,
		Drives:      getAvailableDrives(),
	})
}

// getAvailableDrives returns available drives on Windows
func getAvailableDrives() []string {
	var drives []string
	
	// Check common Windows drive letters
	for _, drive := range "CDEFGHIJKLMNOPQRSTUVWXYZ" {
		drivePath := string(drive) + ":\\"
		if _, err := os.Stat(drivePath); err == nil {
			drives = append(drives, drivePath)
		}
	}
	
	// If no drives found (Unix), return root
	if len(drives) == 0 {
		drives = append(drives, "/")
	}
	
	return drives
}

// handleGetRecentPaths returns recently scanned paths
func handleGetRecentPaths(c *gin.Context) {
	var recentScans []LocalScanResult
	db.Order("created_at desc").Limit(10).Find(&recentScans)
	
	// Extract unique paths
	pathMap := make(map[string]bool)
	var paths []string
	
	for _, scan := range recentScans {
		if !pathMap[scan.Path] {
			pathMap[scan.Path] = true
			paths = append(paths, scan.Path)
		}
	}
	
	c.JSON(http.StatusOK, gin.H{"paths": paths})
}

// handleGetLocalScanHistory returns history of local scans
func handleGetLocalScanHistory(c *gin.Context) {
	var scans []LocalScanResult
	db.Order("created_at desc").Limit(50).Find(&scans)
	
	c.JSON(http.StatusOK, scans)
}

// handleGetLocalScan returns a specific local scan by ID
func handleGetLocalScan(c *gin.Context) {
	scanID := c.Param("scan_id")
	
	var scan LocalScanResult
	if err := db.First(&scan, scanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}
	
	c.JSON(http.StatusOK, scan)
}
