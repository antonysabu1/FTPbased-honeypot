import os
import time
import posixpath

class VirtualNode:
    def __init__(self, name, is_dir=False, content=b"", permissions="rw-r--r--", owner="root", group="root"):
        self.name = name
        self.is_dir = is_dir
        self.content = content if isinstance(content, bytes) else content.encode('utf-8')
        self.permissions = permissions
        self.owner = owner
        self.group = group
        self.mtime = time.time()
        self.children = {} if is_dir else None

    @property
    def size(self):
        if self.is_dir:
            return 4096
        return len(self.content)

class VirtualFileSystem:
    def __init__(self):
        self.root = VirtualNode("", is_dir=True)
        self.populate_default_fs()

    def _add_node(self, path, node):
        parts = [p for p in path.strip("/").split("/") if p]
        curr = self.root
        for part in parts[:-1]:
            if part not in curr.children or not curr.children[part].is_dir:
                curr.children[part] = VirtualNode(part, is_dir=True)
            curr = curr.children[part]
        curr.children[parts[-1]] = node

    def populate_default_fs(self):
        # Create directory skeleton
        dirs = [
            "/etc",
            "/var",
            "/var/www",
            "/var/www/html",
            "/var/log",
            "/home",
            "/home/admin",
            "/tmp",
            "/root",
            "/bin",
            "/usr",
            "/usr/bin"
        ]
        for d in dirs:
            parts = [p for p in d.strip("/").split("/") if p]
            curr = self.root
            for part in parts:
                if part not in curr.children:
                    curr.children[part] = VirtualNode(part, is_dir=True, permissions="rwxr-xr-x")
                curr = curr.children[part]

        # Files
        passwd_content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "sync:x:4:65534:sync:/bin:/bin/sync\n"
            "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
            "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
            "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
            "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
            "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
            "admin:x:1000:1000:Admin User,,,:/home/admin:/bin/bash\n"
            "ftp:x:1001:1001:FTP User,,,:/srv/ftp:/bin/false\n"
        )
        self._add_node("/etc/passwd", VirtualNode("passwd", is_dir=False, content=passwd_content, permissions="r--r--r--"))

        shadow_content = (
            "root:$6$v.9Q2k8Y$a8eJ3H1xM5oL0kP8yR7tU4vW1zX9qN2bC3vF6mK0pS4::0:99999:7:::\n"
            "admin:$6$P0g9L.k1$N3x2.F9aR8tY7uI6oP5lL4kJ3hG2fD1sS9aD8fG7hJ6::0:99999:7:::\n"
            "www-data:*:19200:0:99999:7:::\n"
        )
        self._add_node("/etc/shadow", VirtualNode("shadow", is_dir=False, content=shadow_content, permissions="---------", owner="root", group="shadow"))

        self._add_node("/etc/hostname", VirtualNode("hostname", is_dir=False, content="debian-prod-srv01\n"))
        self._add_node("/etc/issue", VirtualNode("issue", is_dir=False, content="Debian GNU/Linux 11 \\n \\l\n\n"))

        config_php = (
            "<?php\n"
            "// Database connection configuration\n"
            "define('DB_HOST', '127.0.0.1');\n"
            "define('DB_USER', 'db_admin');\n"
            "define('DB_PASS', 'P@ssw0rd2026!Secured');\n"
            "define('DB_NAME', 'production_cms');\n\n"
            "$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);\n"
            "if ($conn->connect_error) {\n"
            "    die('Connection failed: ' . $conn->connect_error);\n"
            "}\n"
            "?>\n"
        )
        self._add_node("/var/www/config.php", VirtualNode("config.php", is_dir=False, content=config_php, owner="www-data", group="www-data"))
        self._add_node("/var/www/html/config.php", VirtualNode("config.php", is_dir=False, content=config_php, owner="www-data", group="www-data"))

        index_php = (
            "<?php\n"
            "require_once 'config.php';\n"
            "echo '<h1>Welcome to Production Portal</h1>';\n"
            "?>\n"
        )
        self._add_node("/var/www/html/index.php", VirtualNode("index.php", is_dir=False, content=index_php, owner="www-data", group="www-data"))

        syslog_content = (
            "Aug  9 04:12:01 debian-prod-srv01 CRON[1234]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))\n"
            "Aug  9 05:00:15 debian-prod-srv01 sshd[5678]: Accepted password for admin from 192.168.1.50 port 49152 ssh2\n"
            "Aug  9 06:15:30 debian-prod-srv01 proftpd[8910]: FTP session opened.\n"
        )
        self._add_node("/var/log/syslog", VirtualNode("syslog", is_dir=False, content=syslog_content, owner="root", group="adm"))

        readme_content = "INTERNAL NOTICE: Database backup is performed every Sunday at 02:00 AM UTC. Contact sysadmin for credentials.\n"
        self._add_node("/home/admin/readme.txt", VirtualNode("readme.txt", is_dir=False, content=readme_content, owner="admin", group="admin"))

        backup_sql = (
            "-- MySQL dump 10.13  Distrib 8.0.28, for Linux (x86_64)\n"
            "CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(50), pass_hash VARCHAR(255));\n"
            "INSERT INTO users VALUES (1, 'superadmin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.eu96g1O.C');\n"
        )
        self._add_node("/home/admin/backup.sql", VirtualNode("backup.sql", is_dir=False, content=backup_sql, owner="admin", group="admin"))

    def normalize_path(self, current_cwd, target_path):
        if not target_path:
            return current_cwd
        if target_path.startswith("/"):
            combined = target_path
        else:
            combined = posixpath.join(current_cwd, target_path)
        
        normalized = posixpath.normpath(combined)
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        return normalized

    def get_node(self, path):
        normalized = posixpath.normpath(path)
        if normalized in ["/", ""]:
            return self.root

        parts = [p for p in normalized.strip("/").split("/") if p]
        curr = self.root
        for part in parts:
            if not curr.is_dir or part not in curr.children:
                return None
            curr = curr.children[part]
        return curr

    def list_dir(self, path):
        node = self.get_node(path)
        if not node or not node.is_dir:
            return None
        
        entries = []
        for name, child in node.children.items():
            type_flag = "d" if child.is_dir else "-"
            perms = child.permissions
            size = child.size
            mtime_str = time.strftime("%b %d %H:%M", time.localtime(child.mtime))
            # e.g., drwxr-xr-x 2 root root 4096 Aug  9 10:00 etc
            line = f"{type_flag}{perms} 1 {child.owner} {child.group} {size:8d} {mtime_str} {name}"
            entries.append(line)
        return entries

    def nlist_dir(self, path):
        node = self.get_node(path)
        if not node or not node.is_dir:
            return None
        return list(node.children.keys())

    def get_file_content(self, path):
        node = self.get_node(path)
        if not node or node.is_dir:
            return None
        return node.content

    def add_file(self, path, content, owner="www-data", group="www-data"):
        normalized = posixpath.normpath(path)
        filename = posixpath.basename(normalized)
        parent_dir = posixpath.dirname(normalized)
        
        parent_node = self.get_node(parent_dir)
        if not parent_node or not parent_node.is_dir:
            # Create parent directories if needed
            parts = [p for p in parent_dir.strip("/").split("/") if p]
            curr = self.root
            for part in parts:
                if part not in curr.children or not curr.children[part].is_dir:
                    curr.children[part] = VirtualNode(part, is_dir=True, permissions="rwxr-xr-x")
                curr = curr.children[part]
            parent_node = curr

        new_node = VirtualNode(filename, is_dir=False, content=content, owner=owner, group=group)
        parent_node.children[filename] = new_node
        return True

    def remove_node(self, path):
        normalized = posixpath.normpath(path)
        filename = posixpath.basename(normalized)
        parent_dir = posixpath.dirname(normalized)

        parent_node = self.get_node(parent_dir)
        if parent_node and parent_node.is_dir and filename in parent_node.children:
            del parent_node.children[filename]
            return True
        return False

    def create_dir(self, path):
        normalized = posixpath.normpath(path)
        filename = posixpath.basename(normalized)
        parent_dir = posixpath.dirname(normalized)

        parent_node = self.get_node(parent_dir)
        if parent_node and parent_node.is_dir:
            parent_node.children[filename] = VirtualNode(filename, is_dir=True, permissions="rwxr-xr-x")
            return True
        return False

    def is_protected_path(self, path):
        """V3: True for system paths that must not be destroyed via DELE/RMD.

        The VFS is SHARED across all attacker sessions, so a destructive command
        (DELE /etc/passwd) would degrade intelligence for every other session.
        Protect the OS-critical top-level trees while leaving decoy dirs
        (/var/www, /home/admin, /tmp) writable for realism.
        """
        normalized = posixpath.normpath(path or "/")
        if normalized in ("/", ""):
            return True
        top = normalized.strip("/").split("/", 1)[0]
        return top in ("etc", "bin", "usr", "sbin", "lib", "boot", "root", "dev", "proc", "sys")
