#!/bin/bash
cleanup () {
  # These files are created by the Jenkinsfile build process
  # Once this script completes we don't need them anymore
  echo "[INFO] Clean up local certificates"
  rm -rf /etc/ansible/id_rsa
  rm -rf /etc/ansible/id_rsa.pub
}

use_env_keys () {
  # If environment variables are passed containing keys, we'll use them
  echo "[INFO] Installing SSH keys..."
  # /all/ansible/[AWS_ACCOUNT_ALIAS]/sa-admin/ansible_ssh_private_key
  echo "${ANSIBLE_SSH_PRIVATE_KEY}" > /root/.ssh/id_rsa
  # /all/ansible/[AWS_ACCOUNT_ALIAS]/sa-admin/ansible_ssh_public_key
  echo "${ANSIBLE_SSH_PUBLIC_KEY}" > /root/.ssh/id_rsa.pub
}

use_container_keys () {
  # If environment variables are not passed through, we'll use the local copies
  echo "[INFO] Installing SSH keys..."
  cp /etc/ansible/id_rsa /root/.ssh/id_rsa
  cp /etc/ansible/id_rsa.pub /root/.ssh/id_rsa.pub
}

set_key_permissions () {
  # SSH key files should be set to r-- (600)
  echo "[INFO] Configuring SSH key permissions..."
  chmod 600 /root/.ssh/id_rsa*
}

use_local_keys () {
  # Use local keys when environment variables are not found
  if [[ -f "/etc/ansible/id_rsa" && -f "/etc/ansible/id_rsa.pub" ]]; then
    echo "[INFO] Ansible SSH keys detected on the filesystem."
    use_container_keys
    if [[ $(stat -c "%a" "/root/.ssh/id_rsa") == "600" && $(stat -c "%a" "/root/.ssh/id_rsa.pub") == "600" ]]; then
      echo "[INFO] SSH Key permissions are set correctly."
    else
      set_key_permissions
    fi
  else
    echo "[ERROR] Unable to locate Ansible SSH keys."
    exit 1
  fi
}

# Trigger cleanup on exit
trap cleanup EXIT

# Check for Ansible keys in environment variables
if [[ $ANSIBLE_SSH_PRIVATE_KEY == *"BEGIN RSA PRIVATE KEY"* ]]; then
    echo "[INFO] Ansible SSH keys detected in the environment."
    if [[ -n "$ANSIBLE_SSH_PUBLIC_KEY" ]]; then
      use_env_keys
      set_key_permissions
    else
      echo "[WARN] Ansible SSH keys not detected in the environment."
      use_local_keys
    fi
else
    echo "[WARN] Ansible SSH keys not detected in the environment."
    use_local_keys
fi
