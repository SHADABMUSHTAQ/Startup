# WarSOC Production MongoDB Backup

Azure cold archives are compliance records, not a complete database backup.
The production backup job creates a compressed MongoDB archive, encrypts it
locally, uploads the encrypted file and SHA-256 sidecar to a separate private
Azure container, and retains only a short local cache.

## Installation

1. Create the private `warsoc-db-backups` container.
2. Create a container-scoped HTTPS SAS with only the permissions needed to
   create and write blobs.
3. Copy `deploy/backup.env.example` to `/etc/warsoc/backup.env`, fill both
   secrets, set owner to `root`, and set mode `600`.
4. Make `scripts/backup_mongodb.sh` executable.
5. Run it once interactively and confirm both uploaded files exist.
6. Add the following root cron entry, replacing the repository path:

   ```cron
   17 2 * * * cd /opt/warsoc/Startup-backend && ./scripts/backup_mongodb.sh >> /var/log/warsoc-backup.log 2>&1
   ```

Enable blob soft delete and a lifecycle rule for the backup container. Enable
DigitalOcean Droplet backups as a second, provider-independent recovery layer.

## Restore Verification

At least monthly, restore the newest backup into a disposable MongoDB 7
container:

1. Verify the encrypted file against its SHA-256 sidecar.
2. Decrypt with `openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000`.
3. Restore with `mongorestore --archive --gzip` into the disposable database.
4. Confirm tenants, users, agents, alerts, evidence metadata, and indexes.
5. Destroy the disposable environment and record the test result.

A backup is not launch-accepted until one complete restore has succeeded.
