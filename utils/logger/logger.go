package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"bc_abe/utils/pathutil"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// Logger 全局日志器。
type Logger struct {
	module     string
	level      Level
	console    bool
	dir        string
	currentDay string
	file       *os.File
	mu         sync.Mutex
}

var (
	globalLevel = LevelInfo
	logDir      = pathutil.Abs("./data/logs")
)

// Init 初始化全局日志目录与级别。
func Init(dir, level string) {
	logDir = dir
	globalLevel = parseLevel(level)
	_ = os.MkdirAll(dir, 0o755)
}

func parseLevel(s string) Level {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// New 创建模块日志器。
func New(module string) *Logger {
	return &Logger{module: module, level: globalLevel, console: true}
}

// SilentConsole 关闭控制台输出（用于脚本/建表等噪音场景）。
func (l *Logger) SilentConsole() *Logger {
	l.console = false
	return l
}

func (l *Logger) Debug(format string, args ...any) { l.log(LevelDebug, format, args...) }
func (l *Logger) Info(format string, args ...any)  { l.log(LevelInfo, format, args...) }
func (l *Logger) Warn(format string, args ...any)  { l.log(LevelWarn, format, args...) }
func (l *Logger) Error(format string, args ...any) { l.log(LevelError, format, args...) }

func (l *Logger) log(level Level, format string, args ...any) {
	if level < l.level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	now := time.Now()
	line := fmt.Sprintf("%s [%s] [%s] %s\n", now.Format("2006-01-02 15:04:05"), levelName(level), l.module, msg)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.console {
		fmt.Fprint(os.Stdout, colorize(level, line))
	}
	writer, err := l.ensureFile(now)
	if err == nil {
		_, _ = io.WriteString(writer, line)
	}
}

func (l *Logger) ensureFile(now time.Time) (io.Writer, error) {
	dir := l.dir
	if dir == "" {
		dir = logDir
	}
	day := now.Format("2006-01-02")
	if l.file != nil && l.currentDay == day {
		return l.file, nil
	}
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return os.Stderr, err
	}
	cleanupOldLogs(dir, 7)
	path := filepath.Join(dir, fmt.Sprintf("%s.log", day))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return os.Stderr, err
	}
	l.file = f
	l.currentDay = day
	return f, nil
}

func cleanupOldLogs(dir string, keepDays int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -keepDays)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

func levelName(level Level) string {
	switch level {
	case LevelDebug:
		return "DEBUG"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

func colorize(level Level, line string) string {
	switch level {
	case LevelDebug:
		return "\033[36m" + line + "\033[0m"
	case LevelWarn:
		return "\033[33m" + line + "\033[0m"
	case LevelError:
		return "\033[31m" + line + "\033[0m"
	default:
		return line
	}
}
