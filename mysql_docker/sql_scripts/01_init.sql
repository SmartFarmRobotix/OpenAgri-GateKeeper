CREATE DATABASE IF NOT EXISTS gatekeeper;
ALTER DATABASE gatekeeper CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'gatekeeper_admin'@'%' IDENTIFIED BY 'asdasdasd';
GRANT ALL PRIVILEGES ON gatekeeper.* TO 'gatekeeper_admin'@'%';
GRANT ALL PRIVILEGES ON `test_gatekeeper`.* TO 'gatekeeper_admin'@'%';
