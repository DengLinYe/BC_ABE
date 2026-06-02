package pathutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const rootModule = "bc_abe"

var (
	rootOnce sync.Once
	rootDir  string
)

// Root 返回项目根目录（含 go.mod module bc_abe）。
func Root() string {
	rootOnce.Do(func() {
		rootDir = detectRoot()
	})
	return rootDir
}

// Abs 将相对项目根的路径转为绝对路径。
func Abs(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	rel = filepath.Clean(rel)
	if rel == "." {
		return Root()
	}
	return filepath.Join(Root(), rel)
}

// ResetForTest 重置根目录缓存，仅供单元测试使用。
func ResetForTest() {
	rootOnce = sync.Once{}
	rootDir = ""
}

func detectRoot() string {
	if v := os.Getenv("BC_ABE_ROOT"); v != "" {
		if isProjectRoot(v) {
			return v
		}
	}
	dir, err := os.Getwd()
	if err != nil {
		return detectRootFromCaller()
	}
	for {
		if isProjectRoot(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return detectRootFromCaller()
}

func detectRootFromCaller() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	dir := filepath.Dir(file)
	for {
		if isProjectRoot(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}

func isProjectRoot(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "module ") {
			continue
		}
		mod := strings.TrimSpace(strings.TrimPrefix(line, "module "))
		if idx := strings.Index(mod, " "); idx >= 0 {
			mod = mod[:idx]
		}
		return mod == rootModule
	}
	return false
}
