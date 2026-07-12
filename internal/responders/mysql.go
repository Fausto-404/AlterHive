package responders

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"sync"

	"github.com/alterhive/alterhive/internal/domain"
)

// mysqlSessionState tracks per-session MySQL context.
type mysqlSessionState struct {
	CurrentDB   string
	UDFProgress int // 0=none, 1=plugin_dir_checked, 2=dumpfile_attempted, 3=udf_created
	QueryCount  int
}

var (
	mysqlSessionsMu sync.RWMutex
	mysqlSessions   = make(map[string]*mysqlSessionState)
)

var (
	mysqlDenied = "ERROR 1045 (28000): Access denied for user '%s'@'192.168.56.23' (using password: YES)\n"

	mysqlWelcome = "Welcome to the MySQL monitor.  Commands end with ; or \\g.\n" +
		"Your MySQL connection id is 42\n" +
		"Server version: 5.7.38 MySQL Community Server (GPL)\n\n" +
		"Copyright (c) 2000, 2023, Oracle and/or its affiliates.\n\n" +
		"Type 'help;' or '\\h' for help. Type '\\c' to clear the current input statement.\n\n"

	showDatabases = "+--------------------+\n" +
		"| Database           |\n" +
		"+--------------------+\n" +
		"| information_schema |\n" +
		"| fin_readonly_" + domain.DeploySeed + " |\n" +
		"+--------------------+\n" +
		"2 rows in set (0.00 sec)\n"

	showTables = "+-------------------------+\n" +
		"| Tables_in_fin_readonly_" + domain.DeploySeed + " |\n" +
		"+-------------------------+\n" +
		"| accounts               |\n" +
		"| audit_log              |\n" +
		"| transactions           |\n" +
		"| users                  |\n" +
		"+-------------------------+\n" +
		"4 rows in set (0.00 sec)\n"

	selectAccounts = "+----+--------------+----------------+---------------------+\n" +
		"| id | account_name | balance        | last_updated        |\n" +
		"+----+--------------+----------------+---------------------+\n" +
		"|  1 | Operating    |     1523456.78 | 2024-01-15 08:15:22 |\n" +
		"|  2 | Payroll      |      234567.89 | 2024-01-15 06:30:00 |\n" +
		"|  3 | Reserve      |     5678901.23 | 2024-01-14 23:59:59 |\n" +
		"|  4 | Marketing    |       45678.90 | 2024-01-15 08:00:00 |\n" +
		"|  5 | IT_Budget    |       89012.34 | 2024-01-15 07:45:30 |\n" +
		"+----+--------------+----------------+---------------------+\n" +
		"5 rows in set (0.01 sec)\n"

	selectTransactions = "+----+------------+--------+---------------------+-------------+\n" +
		"| id | account_id | amount | timestamp           | description |\n" +
		"+----+------------+--------+---------------------+-------------+\n" +
		"|  1 |          1 | -50000 | 2024-01-15 08:15:22 | Wire transfer to vendor |\n" +
		"|  2 |          1 |  12500 | 2024-01-15 07:30:00 | Client payment received |\n" +
		"|  3 |          2 | -35000 | 2024-01-15 06:30:00 | Payroll disbursement    |\n" +
		"|  4 |          3 | 100000 | 2024-01-14 23:59:59 | End-of-day sweep        |\n" +
		"|  5 |          1 |  -8900 | 2024-01-15 08:00:00 | Software license renewal|\n" +
		"+----+------------+--------+---------------------+-------------+\n" +
		"5 rows in set (0.00 sec)\n"

	selectUsers = "+----+----------+-------------------------------------------+---------------------+\n" +
		"| id | username | password_hash                             | last_login          |\n" +
		"+----+----------+-------------------------------------------+---------------------+\n" +
		"|  1 | admin    | $2b$12$LJ3m4ys8Gt5rKz6R4v5X6OQ7v8w9x0y1z  | 2024-01-15 08:15:45 |\n" +
		"|  2 | svc_web  | $2b$12$M9n0o1p2q3r4s5t6u7v8w9x0y1z2a3b4c  | 2024-01-15 08:01:13 |\n" +
		"|  3 | readonly | $2b$12$N0o1p2q3r4s5t6u7v8w9x0y1z2a3b4c5d  | 2024-01-14 22:00:00 |\n" +
		"|  4 | backup   | $2b$12$O1p2q3r4s5t6u7v8w9x0y1z2a3b4c5d6e  | 2024-01-15 04:00:00 |\n" +
		"+----+----------+-------------------------------------------+---------------------+\n" +
		"4 rows in set (0.01 sec)\n"

	selectAuditLog = "+----+---------+---------------------+-------------------+------------------------------------------+\n" +
		"| id | user_id | timestamp           | action            | detail                                   |\n" +
		"+----+---------+---------------------+-------------------+------------------------------------------+\n" +
		"|  1 |       1 | 2024-01-15 08:15:45 | login_success     | Login from 192.168.56.23                 |\n" +
		"|  2 |       1 | 2024-01-15 08:15:22 | query_execute     | SELECT * FROM transactions               |\n" +
		"|  3 |       2 | 2024-01-15 08:01:13 | login_success     | Service account login from 127.0.0.1    |\n" +
		"|  4 |       3 | 2024-01-14 22:00:00 | query_execute     | SELECT balance FROM accounts             |\n" +
		"|  5 |       4 | 2024-01-15 04:00:00 | backup_started    | Full database backup initiated           |\n" +
		"+----+---------+---------------------+-------------------+------------------------------------------+\n" +
		"5 rows in set (0.00 sec)\n"

	mysqldumpOutput = "-- MySQL dump 10.16  Distrib 5.7.38, for Linux (x86_64)\n" +
		"-- Host: 192.168.56.60    Database: fin_readonly_" + domain.DeploySeed + "\n" +
		"-- Server version\t5.7.38\n\n" +
		"USE `fin_readonly_" + domain.DeploySeed + "`;\n\n" +
		"DROP TABLE IF EXISTS `accounts`;\n" +
		"CREATE TABLE `accounts` (\n" +
		"  `id` int(11) NOT NULL AUTO_INCREMENT,\n" +
		"  `account_name` varchar(100) NOT NULL,\n" +
		"  `balance` decimal(15,2) NOT NULL DEFAULT '0.00',\n" +
		"  `last_updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,\n" +
		"  PRIMARY KEY (`id`)\n" +
		") ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=latin1;\n\n" +
		"LOCK TABLES `accounts` WRITE;\n" +
		"INSERT INTO `accounts` VALUES (1,'Operating',1523456.78,'2024-01-15 08:15:22'),(2,'Payroll',234567.89,'2024-01-15 06:30:00'),(3,'Reserve',5678901.23,'2024-01-14 23:59:59'),(4,'Marketing',45678.90,'2024-01-15 08:00:00'),(5,'IT_Budget',89012.34,'2024-01-15 07:45:30');\n" +
		"UNLOCK TABLES;\n"

	reMySQLHost = regexp.MustCompile(`-h\s+(\S+)`)
	reMySQLUser = regexp.MustCompile(`-u\s+(\S+)`)
)

// sessionAccounts returns session-varying account names.
func sessionAccounts(sessionID string) []string {
	seed := domain.SessionSeed(sessionID)
	rng := rand.New(rand.NewSource(seed))
	pool := []string{"Operating", "Payroll", "Reserve", "Marketing", "IT_Budget", "Treasury", "Holdings", "Escrow"}
	rng.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	return pool[:5]
}

// sessionBalances returns 5 session-varying balance values.
func sessionBalances(sessionID string) []string {
	seed := domain.SessionSeed(sessionID + "_bal")
	rng := rand.New(rand.NewSource(seed))
	vals := make([]string, 5)
	for i := range vals {
		bal := 10000.0 + float64(rng.Intn(9900000))/100.0
		vals[i] = fmt.Sprintf("%14.2f", bal)
	}
	return vals
}

// sessionTimestamps returns 5 session-varying timestamp strings.
func sessionTimestamps(sessionID string, baseOffset int) []string {
	ts := make([]string, 5)
	for i := range ts {
		ts[i] = domain.SeedTimeStr(nil, baseOffset+i*rngSeedOffset(sessionID, i))
	}
	return ts
}

func rngSeedOffset(sessionID string, idx int) int {
	seed := domain.SessionSeed(sessionID + fmt.Sprintf("_ts%d", idx))
	return int(seed%120) + 30
}

// buildMysqldumpOutput generates session-varying mysqldump output.
func buildMysqldumpOutput(sessionID string) string {
	names := sessionAccounts(sessionID)
	bals := sessionBalances(sessionID)
	tss := sessionTimestamps(sessionID, 60)
	out := "-- MySQL dump 10.16  Distrib 5.7.38, for Linux (x86_64)\n" +
		"-- Host: 192.168.56.60    Database: fin_readonly_" + domain.DeploySeed + "\n" +
		"-- Server version\t5.7.38\n\n" +
		"USE `fin_readonly_" + domain.DeploySeed + "`;\n\n" +
		"DROP TABLE IF EXISTS `accounts`;\n" +
		"CREATE TABLE `accounts` (\n" +
		"  `id` int(11) NOT NULL AUTO_INCREMENT,\n" +
		"  `account_name` varchar(100) NOT NULL,\n" +
		"  `balance` decimal(15,2) NOT NULL DEFAULT '0.00',\n" +
		"  `last_updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,\n" +
		"  PRIMARY KEY (`id`)\n" +
		") ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=latin1;\n\n" +
		"LOCK TABLES `accounts` WRITE;\n" +
		"INSERT INTO `accounts` VALUES "
	for i := 0; i < 5; i++ {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("(%d,'%s',%s,'%s')", i+1, names[i], bals[i][1:], tss[i]) // [1:] strips leading space from fmt 14.2
	}
	out += ";\nUNLOCK TABLES;\n"
	return out
}

// getMySQLSession returns (or creates) the per-session state.
func getMySQLSession(sessionID string) *mysqlSessionState {
	mysqlSessionsMu.Lock()
	defer mysqlSessionsMu.Unlock()
	if sessionID == "" {
		sessionID = "_default"
	}
	s, ok := mysqlSessions[sessionID]
	if !ok {
		s = &mysqlSessionState{CurrentDB: "fin_readonly_" + domain.DeploySeed + ""}
		mysqlSessions[sessionID] = s
	}
	return s
}

// HandleMySQLCommand simulates MySQL CLI interaction.
// profileHint is the agent's deception profile (e.g. "credential_reuse", "secret_hunter").
func HandleMySQLCommand(cmd string, ppfTriggered bool, profileHint string, session *domain.SessionContext) (string, []string) {
	var evidenceHits []string
	cmdLower := strings.ToLower(strings.TrimSpace(cmd))
	sessionID := session.SessionID

	// Parse user from command for all mysql/mysqldump/mysqladmin commands
	_, user, _ := parseMySQLArgs(cmd)

	if strings.Contains(cmdLower, "mysql") && strings.Contains(cmdLower, "-p") {
		evidenceHits = append(evidenceHits, "credential_reuse_attempt", "db_probe")
	}

	if strings.HasPrefix(cmdLower, "mysql ") {
		host, _, hasPassword := parseMySQLArgs(cmd)
		_ = host

		// Check for -e flag (execute query and exit)
		query := parseMySQLExecQuery(cmd)

		if !hasPassword {
			return fmt.Sprintf("ERROR 1045 (28000): Access denied for user '%s'@'192.168.56.23' (using password: NO)\n", user), evidenceHits
		}

		evidenceHits = append(evidenceHits, "mysql_auth_success")

		// If -e flag, execute query directly and return
		if query != "" {
			sess := getMySQLSession(session.SessionID)
			return handleMySQLQuery(query, sess, sessionID), evidenceHits
		}

		session.ShellMode = "mysql"
		return mysqlWelcome + showDatabases + "\n", evidenceHits
	}

	// mysqldump
	if strings.HasPrefix(cmdLower, "mysqldump") {
		evidenceHits = append(evidenceHits, "data_exfiltration")
		return buildMysqldumpOutput(session.SessionID), evidenceHits
	}

	// mysqladmin
	if strings.HasPrefix(cmdLower, "mysqladmin") {
		return "Uptime: 54321  Threads: 3  Questions: 12345  Slow queries: 2  Opens: 456  Flush tables: 1  Open tables: 200  Queries per second avg: 0.227\n", evidenceHits
	}

	// MySQL interactive queries
	sess := getMySQLSession(sessionID)
	return handleMySQLQuery(cmdLower, sess, sessionID), evidenceHits
}

// HandleMySQLQuery handles MySQL interactive queries.
func HandleMySQLQuery(query string, sessionID string) string {
	sess := getMySQLSession(sessionID)
	return handleMySQLQuery(strings.ToLower(strings.TrimSpace(query)), sess, sessionID)
}

func LocalizeMySQLOutput(output string, session *domain.SessionContext) string {
	if session == nil {
		return output
	}
	localIP := session.SubnetLocalIP
	if localIP == "" {
		localIP = "192.168.56.23"
	}
	dbIP := cidrHost(session.SubnetCIDR, 60)
	output = strings.ReplaceAll(output, "192.168.56.23", localIP)
	if dbIP != "" {
		output = strings.ReplaceAll(output, "192.168.56.60", dbIP)
	}
	return output
}

func cidrHost(cidr string, lastOctet int) string {
	base := strings.TrimSuffix(cidr, "/24")
	parts := strings.Split(base, ".")
	if len(parts) != 4 {
		return ""
	}
	parts[3] = fmt.Sprintf("%d", lastOctet)
	return strings.Join(parts, ".")
}

func handleMySQLQuery(q string, sess *mysqlSessionState, sessionID string) string {
	q = strings.TrimRight(q, ";")
	q = strings.TrimSpace(q)
	sess.QueryCount++

	// USE database — track context switch
	if strings.HasPrefix(q, "use ") {
		db := strings.TrimSpace(q[4:])
		sess.CurrentDB = db
		return "Database changed\n"
	}

	switch {
	case q == "show databases":
		return showDatabases
	case q == "show tables":
		if sess.CurrentDB == "information_schema" {
			return "+-----------------------+\n| Tables_in_information_schema |\n+-----------------------+\n| COLUMNS              |\n| SCHEMATA             |\n| TABLES               |\n+-----------------------+\n3 rows in set (0.00 sec)\n"
		}
		return showTables

	// Table-specific SELECTs
	case strings.Contains(q, "select") && strings.Contains(q, "accounts"):
		return selectAccounts
	case strings.Contains(q, "select") && strings.Contains(q, "transactions"):
		return selectTransactions
	case strings.Contains(q, "select") && strings.Contains(q, "users"):
		return selectUsers
	case strings.Contains(q, "select") && strings.Contains(q, "audit_log"):
		return selectAuditLog

	// Version queries
	case q == "select version()" || q == "select @@version":
		return "+------------+\n| version()  |\n+------------+\n| 5.7.38     |\n+------------+\n1 row in set (0.00 sec)\n"
	case q == "select @@version_comment":
		return "+---------------------------+\n| @@version_comment         |\n+---------------------------+\n| MySQL Community Server (GPL) |\n+---------------------------+\n1 row in set (0.00 sec)\n"

	// User queries
	case q == "select user()" || q == "select current_user()":
		return "+---------------------+\n| user()              |\n+---------------------+\n| web_ro@192.168.56.23|\n+---------------------+\n1 row in set (0.00 sec)\n"
	case q == "select database()":
		return fmt.Sprintf("+---------------+\n| database()    |\n+---------------+\n| %-13s |\n+---------------+\n1 row in set (0.00 sec)\n", sess.CurrentDB)

	// Plugin dir — triggers UDF progress tracking
	case q == "select @@plugin_dir" || strings.Contains(q, "plugin_dir"):
		sess.UDFProgress = 1
		return "+------------------------------+\n| @@plugin_dir                 |\n+------------------------------+\n| /usr/lib/mysql/plugin/       |\n+------------------------------+\n1 row in set (0.00 sec)\n"

	// LOAD_FILE — file read via MySQL (architecture §23.2)
	case strings.Contains(q, "load_file("):
		path := extractLoadFilePath(q)
		return handleLoadFile(path)

	// INTO DUMPFILE — staged UDF block
	case strings.Contains(q, "into dumpfile"):
		sess.UDFProgress = 2
		return "ERROR 1 (HY000): Can't create/write to file '/usr/lib/mysql/plugin/udf.so' (Errcode: 13 - Permission denied)\n"
	case strings.Contains(q, "into outfile"):
		return "ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement\n"

	// CREATE FUNCTION (UDF) — blocked
	case strings.HasPrefix(q, "create function") || strings.HasPrefix(q, "create aggregate function"):
		return "ERROR 1126 (HY000): Can't open shared library 'udf.so' (errno: 13 - Permission denied)\n"

	// SHOW VARIABLES
	case strings.HasPrefix(q, "show variables"):
		return handleShowVariables(q, sess)
	case q == "show grants":
		return handleShowGrants(sess)
	case q == "show grants for current_user()" || q == "show grants for current_user":
		return handleShowGrants(sess)
	case q == "show processlist":
		return handleShowProcesslist(sess)
	case q == "show status":
		return "+---------------+----------+\n| Variable_name | Value    |\n+---------------+----------+\n| Threads       | 3        |\n| Uptime        | 54321    |\n| Questions     | 12345    |\n| Slow_queries  | 2        |\n+---------------+----------+\n4 rows in set (0.00 sec)\n"
	case q == "show slave status" || q == "show replica status":
		return "Empty set (0.00 sec)\n"
	case strings.HasPrefix(q, "show create table"):
		return "+-------+---------------------------------------------------------------+\n| Table | Create Table                                                  |\n+-------+---------------------------------------------------------------+\n| accounts | CREATE TABLE `accounts` (\n  `id` int(11) NOT NULL AUTO_INCREMENT,\n  `account_name` varchar(100) NOT NULL,\n  `balance` decimal(15,2) NOT NULL DEFAULT '0.00',\n  `last_updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=latin1 |\n+-------+---------------------------------------------------------------+\n1 row in set (0.00 sec)\n"

	// SYSTEM / shell escape from MySQL
	case strings.HasPrefix(q, "system ") || strings.HasPrefix(q, "\\! "):
		return "ERROR 2006 (HY000): MySQL server has gone away\n"

	case q == "quit" || q == "exit":
		return "Bye\n"
	case q == "help":
		return "List of all MySQL commands:\nNote that all text commands must be first on line and end with ';'\n" +
			"?         (\\?) Synonym for `help'.\n" +
			"clear     (\\c) Clear the current input statement.\n" +
			"exit      (\\q) Exit MySQL.\n" +
			"help      (\\h) Display this help.\n" +
			"quit      (\\q) Quit MySQL.\n" +
			"status    (\\s) Get status information from the server.\n" +
			"use       (\\u) Use another database.\n"
	case q == "status":
		return fmt.Sprintf("--------------\n"+
			"mysql  Ver 14.14 Distrib 5.7.38, for Linux (x86_64) using  EditLine wrapper\n\n"+
			"Connection id:          42\n"+
			"Current database:       %s\n"+
			"Current user:           web_ro@192.168.56.23\n"+
			"SSL:                    Not in use\n"+
			"Server version:         5.7.38 MySQL Community Server (GPL)\n"+
			"Protocol version:       10\n"+
			"Connection:             192.168.56.60 via TCP/IP\n"+
			"TCP port:               3306\n"+
			"--------------\n", sess.CurrentDB)

	// Privileged / write operations — denied
	case strings.HasPrefix(q, "insert") || strings.HasPrefix(q, "update") || strings.HasPrefix(q, "delete") || strings.HasPrefix(q, "drop") || strings.HasPrefix(q, "truncate") || strings.HasPrefix(q, "alter") || strings.HasPrefix(q, "create table"):
		return "ERROR 1142 (42000): SELECT command denied to user 'web_ro'@'192.168.56.23' for table '" + sess.CurrentDB + ".accounts'\n"
	case strings.HasPrefix(q, "load data"):
		return "ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement\n"

	default:
		return fmt.Sprintf("ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%s' at line 1\n", q)
	}
}

func handleShowVariables(q string, sess *mysqlSessionState) string {
	// SHOW VARIABLES LIKE '%secure_file_priv%'
	if strings.Contains(q, "secure_file_priv") {
		return "+------------------+----------+\n| Variable_name    | Value    |\n+------------------+----------+\n| secure_file_priv |          |\n+------------------+----------+\n1 row in set (0.00 sec)\n"
	}
	// SHOW VARIABLES LIKE '%plugin%'
	if strings.Contains(q, "plugin") {
		return "+---------------+-------------------------+\n| Variable_name | Value                   |\n+---------------+-------------------------+\n| plugin_dir    | /usr/lib/mysql/plugin/  |\n+---------------+-------------------------+\n1 row in set (0.00 sec)\n"
	}
	// SHOW VARIABLES LIKE '%version%'
	if strings.Contains(q, "version") {
		return "+-------------------------+---------------------+\n| Variable_name           | Value               |\n+-------------------------+---------------------+\n| version                 | 5.7.38              |\n| version_comment         | MySQL Community Server (GPL) |\n| version_compile_machine | x86_64              |\n| version_compile_os      | Linux               |\n+-------------------------+---------------------+\n4 rows in set (0.00 sec)\n"
	}
	// SHOW VARIABLES LIKE '%log%'
	if strings.Contains(q, "log") {
		return "+----------------------------------------+----------------------------+\n| Variable_name                          | Value                      |\n+----------------------------------------+----------------------------+\n| general_log                            | OFF                        |\n| general_log_file                       | /var/lib/mysql/staging-web-01.log |\n| log_bin                                | ON                         |\n| log_bin_basename                       | /var/lib/mysql/mysql-bin   |\n| log_error                              | /var/log/mysql/error.log   |\n+----------------------------------------+----------------------------+\n5 rows in set (0.00 sec)\n"
	}
	// Generic SHOW VARIABLES
	return "+----------------------------------------+----------------------------+\n| Variable_name                          | Value                      |\n+----------------------------------------+----------------------------+\n| auto_increment_increment               | 1                          |\n| auto_increment_offset                   | 1                          |\n| autocommit                             | ON                         |\n| character_set_client                   | utf8                       |\n| character_set_connection               | utf8                       |\n| character_set_results                  | utf8                       |\n| collation_connection                   | utf8_general_ci            |\n| collation_database                     | latin1_swedish_ci          |\n| collation_server                       | latin1_swedish_ci          |\n| connect_timeout                        | 10                         |\n| datadir                                | /var/lib/mysql/            |\n| default_storage_engine                 | InnoDB                     |\n| disabled_storage_engines               |                            |\n| explicit_defaults_for_timestamp        | OFF                        |\n| have_ssl                               | DISABLED                   |\n| hostname                               | staging-web-01             |\n| init_connect                           |                            |\n| interactive_timeout                    | 28800                      |\n| local_infile                           | ON                         |\n| lock_wait_timeout                      | 31536000                   |\n| log_bin                                | ON                         |\n| log_bin_trust_function_creators        | OFF                        |\n| max_allowed_packet                     | 4194304                    |\n| max_connect_errors                     | 100                        |\n| max_connections                        | 151                        |\n| max_user_connections                   | 0                          |\n| pid_file                               | /var/run/mysqld/mysqld.pid |\n| plugin_dir                             | /usr/lib/mysql/plugin/     |\n| port                                   | 3306                       |\n| report_host                            | staging-web-01             |\n| secure_auth                            | ON                         |\n| secure_file_priv                       |                            |\n| server_id                              | 1                          |\n| skip_external_locking                  | ON                         |\n| socket                                 | /var/run/mysqld/mysqld.sock |\n| sql_mode                               | STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION |\n| system_time_zone                       | UTC                        |\n| table_open_cache                       | 2000                       |\n| time_zone                              | SYSTEM                     |\n| tmpdir                                 | /tmp                       |\n| tx_isolation                           | REPEATABLE-READ            |\n| wait_timeout                           | 28800                      |\n+----------------------------------------+----------------------------+\n43 rows in set (0.01 sec)\n"
}

func handleShowGrants(sess *mysqlSessionState) string {
	return "+---------------------------------------------------------------------------+\n| Grants for web_ro@192.168.56.23                                           |\n+---------------------------------------------------------------------------+\n| GRANT USAGE ON *.* TO 'web_ro'@'192.168.56.23' IDENTIFIED BY PASSWORD '*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9' |\n| GRANT SELECT ON `fin_readonly_" + domain.DeploySeed + "`.* TO 'web_ro'@'192.168.56.23'        |\n| GRANT SELECT ON `information_schema`.* TO 'web_ro'@'192.168.56.23'        |\n+---------------------------------------------------------------------------+\n3 rows in set (0.00 sec)\n"
}

func handleShowProcesslist(sess *mysqlSessionState) string {
	return "+----+----------+---------------------+--------------------+---------+------+-----------+------------------+\n| Id | User     | Host                | db                 | Command | Time | State     | Info             |\n+----+----------+---------------------+--------------------+---------+------+-----------+------------------+\n| 42 | web_ro   | 192.168.56.23:54321 | fin_readonly_" + domain.DeploySeed + " | Query   |    0 | starting  | show processlist |\n| 38 | svc_web  | 127.0.0.1:43210     | fin_readonly_" + domain.DeploySeed + " | Sleep   |  120 |           | NULL             |\n+----+----------+---------------------+--------------------+---------+------+-----------+------------------+\n2 rows in set (0.00 sec)\n"
}

func parseMySQLArgs(command string) (host, user string, hasPassword bool) {
	host = "192.168.56.60"
	user = "web_ro"
	hasPassword = false

	if m := reMySQLHost.FindStringSubmatch(command); len(m) > 1 {
		host = m[1]
	}
	if m := reMySQLUser.FindStringSubmatch(command); len(m) > 1 {
		user = m[1]
	}
	if strings.Contains(command, "-p") {
		hasPassword = true
	}
	return
}

// parseMySQLExecQuery extracts the query from -e flag.
func parseMySQLExecQuery(command string) string {
	// Match -e "query" or -e 'query' or -equery
	re := regexp.MustCompile(`-e\s*["']([^"']+)["']`)
	if m := re.FindStringSubmatch(command); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	// Match -equery (no space, no quotes)
	re2 := regexp.MustCompile(`-e(\S+)`)
	if m := re2.FindStringSubmatch(command); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// extractLoadFilePath pulls the file path argument from a LOAD_FILE('...') call.
func extractLoadFilePath(q string) string {
	re := regexp.MustCompile(`(?i)load_file\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	if m := re.FindStringSubmatch(q); len(m) > 1 {
		return m[1]
	}
	return ""
}

// handleLoadFile returns MySQL LOAD_FILE output for a given path.
// Per architecture §23.2/§24.3: system files return NULL (permission denied
// at the OS layer), whitelisted decoy files return truncated content, and
// everything else returns NULL to avoid giving the attacker real file access.
func handleLoadFile(path string) string {
	nullResult := "+----------------------+\n| NULL                 |\n+----------------------+\n1 row in set (0.00 sec)\n"
	lower := strings.ToLower(path)
	switch lower {
	case "/etc/passwd":
		return "+----------------------+\n| LOAD_FILE('/etc/passwd')  |\n+----------------------+\n| root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\ndeploy:x:1001:1001::/home/deploy:/bin/bash\nmysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false\n |\n+----------------------+\n1 row in set (0.00 sec)\n"
	case "/etc/hostname":
		return "+----------------------+\n| staging-web-01\n |\n+----------------------+\n1 row in set (0.00 sec)\n"
	case "/var/www/html/config.php":
		return "+----------------------+\n| <?php\n$db_host = '192.168.56.60';\n$db_user = 'web_ro';\n$db_pass = 'WebApp@2024!Ro';\n |\n+----------------------+\n1 row in set (0.00 sec)\n"
	default:
		return nullResult
	}
}
