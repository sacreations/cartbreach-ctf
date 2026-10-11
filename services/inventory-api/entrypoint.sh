#!/bin/sh
set -e

# Create non-root service user
addgroup -g 1001 inventory-svc || true
adduser -u 1001 -G inventory-svc -s /bin/bash -D inventory-svc || true

# Plant Stage 5 user flag
echo "SLIIT{c4rt_br34ch_c0mm4nd_1nj3ct_sh3ll}" > /home/inventory-svc/user.txt
chown inventory-svc:inventory-svc /home/inventory-svc/user.txt
chmod 0640 /home/inventory-svc/user.txt

# Plant Stage 6 root flag
echo "SLIIT{c4rt_br34ch_r00t_cr0n_pr1v35c}" > /root/root.txt
chmod 0600 /root/root.txt

# Stage 6 vulnerable cron script: chmod 777 (world-writable)
mkdir -p /opt/scripts
cat << 'EOF' > /opt/scripts/sync_orders.sh
#!/bin/sh
# Scheduled order sync worker — runs every 2 minutes as root
echo "[$(date)] Syncing inventory state with PostgreSQL..." >> /var/log/sync_orders.log
EOF
chmod 777 /opt/scripts/sync_orders.sh

# Install root crontab: runs every 2 minutes
echo "*/2 * * * * /opt/scripts/sync_orders.sh" | crontab -

# Start crond daemon in background
crond -b -l 8

# Start interactive web terminal daemon as inventory-svc on port 7681
chown -R inventory-svc:inventory-svc /home/inventory-svc
ttyd -p 7681 -i 0.0.0.0 -b /terminal -W \
     -t fontSize=14 \
     -t fontFamily="'JetBrains Mono', 'DM Mono', monospace" \
     -t theme='{"background": "#090c10", "foreground": "#f1f5f9", "cursor": "#ff6b35", "selectionBackground": "#8b5cf6"}' \
     su-exec inventory-svc /bin/bash -l &

# Run FastAPI app as inventory-svc user
exec su-exec inventory-svc uvicorn main:app --host 0.0.0.0 --port 8000
