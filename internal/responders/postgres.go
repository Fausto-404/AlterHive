package responders

import (
	"strings"

	"github.com/alterhive/alterhive/internal/domain"
)

func HandlePostgresCommand(cmd string, session *domain.SessionContext, ppfTriggered bool) (string, []string) {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	hits := []string{"db_probe"}
	if strings.HasPrefix(lower, "pg_dump") {
		return "-- PostgreSQL database dump\n-- Dumped from database version 13.12\n-- partial schema only; table data access denied by row-level security\nCREATE SCHEMA audit;\nCREATE TABLE audit.deploy_events(id integer, actor text, created_at timestamp);\n", append(hits, "data_exfiltration")
	}
	if strings.Contains(lower, "-c") && strings.Contains(lower, "version()") {
		return "PostgreSQL 13.12 on x86_64-pc-linux-gnu, compiled by gcc, 64-bit\n", hits
	}
	if strings.Contains(lower, "copy") && strings.Contains(lower, "program") {
		return "ERROR:  must be superuser or a member of the pg_execute_server_program role to COPY to or from an external program\n", hits
	}
	if strings.Contains(lower, "pg_read_file") {
		return "ERROR:  permission denied for function pg_read_file\n", hits
	}
	// CREATE EXTENSION — blocked (architecture §23.3)
	if strings.Contains(lower, "create extension") {
		return "ERROR:  permission denied for schema public to create extension \"pg_adminpack\"\nHINT:  Must be superuser to create this extension.\n", hits
	}

	// lo_import / lo_export — large object file access, blocked
	if strings.Contains(lower, "lo_import") {
		return "ERROR:  permission denied for function lo_import\n", hits
	}
	if strings.Contains(lower, "lo_export") {
		return "ERROR:  permission denied for function lo_export\n", hits
	}

	// current_user / current_database — basic enumeration
	if strings.Contains(lower, "current_user") && strings.Contains(lower, "-c") {
		return " app_ro\n(1 row)\n", hits
	}
	if strings.Contains(lower, "current_database") && strings.Contains(lower, "-c") {
		return " fin_archive\n(1 row)\n", hits
	}

	// pg_database enumeration
	if strings.Contains(lower, "pg_database") {
		return "    datname    | datdba | encoding | datcollate | datctype\n---------------+--------+----------+------------+------------\n postgres      |     10 |        6 | C.UTF-8    | C.UTF-8\n fin_archive   |  16384 |        6 | C.UTF-8    | C.UTF-8\n prod_finance  |  16385 |        6 | C.UTF-8    | C.UTF-8\n(3 rows)\n", append(hits, "pseudo_progress")
	}

	// information_schema / pg_tables enumeration
	if strings.Contains(lower, "information_schema") || strings.Contains(lower, "pg_tables") {
		return "    schemaname    |    tablename    | tableowner\n-----------------+-----------------+------------\n public          | accounts        | app_ro\n public          | audit_events    | app_ro\n public          | transactions    | app_ro\n audit           | deploy_events   | postgres\n(4 rows)\n", append(hits, "pseudo_progress")
	}

	if strings.HasPrefix(lower, "psql") {
		return "psql (13.12)\nType \"help\" for help.\n\nfin_archive=> \\dt\n          List of relations\n Schema |     Name      | Type  | Owner\n--------+---------------+-------+--------\n public | accounts      | table | app_ro\n public | audit_events  | table | app_ro\n public | transactions  | table | app_ro\n(3 rows)\n", append(hits, "pseudo_progress")
	}
	return "", hits
}
