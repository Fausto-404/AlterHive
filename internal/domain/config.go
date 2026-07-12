package domain

import (
	"fmt"
	"hash/fnv"
	"time"
)

// DeploySeed is the deployment-specific seed string used throughout the system
// for canary IDs, token prefixes, request IDs, database names, etc.
// Default is "cny42". Override via DEPLOY_SEED environment variable.
var DeploySeed = "cny42"

// StartTime is the time when the AlterHive process started.
// Used as a base for generating plausible timestamps throughout the system.
var StartTime time.Time

func init() {
	StartTime = time.Now()
}

// SeedTime returns a plausible fake timestamp derived from the session start time,
// offset by the given minutes. This ensures timestamps are consistent within a
// session but vary between sessions.
func SeedTime(session *SessionContext, offsetMinutes int) time.Time {
	if session != nil {
		return session.ConnectedAt.Add(-time.Duration(offsetMinutes) * time.Minute)
	}
	return StartTime.Add(-time.Duration(offsetMinutes) * time.Minute)
}

// SeedTimeStr returns a formatted timestamp string (YYYY-MM-DD HH:MM:SS).
func SeedTimeStr(session *SessionContext, offsetMinutes int) string {
	return SeedTime(session, offsetMinutes).Format("2006-01-02 15:04:05")
}

// SeedTimeShort returns a short formatted timestamp (YYYY-MM-DD HH:MM).
func SeedTimeShort(session *SessionContext, offsetMinutes int) string {
	return SeedTime(session, offsetMinutes).Format("2006-01-02 15:04")
}

// DerivePassword generates a deterministic per-host password from the deploy seed and hostname.
// Same seed + hostname always produces the same password; different seeds produce different passwords.
func DerivePassword(hostname string) string {
	h := fnv.New32a()
	h.Write([]byte(DeploySeed + ":" + hostname))
	return fmt.Sprintf("%s%x!", DeploySeed, h.Sum32())
}

// SessionSeed returns a deterministic int64 seed derived from the session ID.
// Use this to get reproducible pseudo-random variation per session.
func SessionSeed(sessionID string) int64 {
	h := fnv.New64a()
	h.Write([]byte(DeploySeed + ":" + sessionID))
	return int64(h.Sum64())
}
