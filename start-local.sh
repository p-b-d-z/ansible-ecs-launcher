#!/bin/bash
# THIS SCRIPT IS USED FOR RUNNING ANSIBLE LOCALLY FROM YOUR WORKSTATION
# Runtime variables
INVENTORY_OS="ubuntu"
ANSIBLE_ENV="ydc"
ANSIBLE_ROLE="octane"
BUSINESS_REGION="amer"
BUSINESS_REGION_UPPER="${BUSINESS_REGION^^}"
# Credentials
# Set using .env
AWS_ACCESS_KEY_ID="placeholder"
AWS_SECRET_ACCESS_KEY="placeholder"
ANSIBLE_SSH_PRIVATE_KEY="placeholder"
ANSIBLE_SSH_PUBLIC_KEY="placeholder"
DATADOG_API_KEY="placeholder"
# Jenkins
BUILD_NUMBER="1"
JOB_BASE_NAME="${ANSIBLE_ROLE}"
BUILD_CAUSE="manual"
BUILD_USER_ID="local"
TARGETED_ENV="ALL"
# shellcheck disable=SC2034
TARGETED_HOST=""
TARGETED_FUNCTION=""
TARGETED_STACK="ALL"
# Ansible
ANSIBLECHECKMODE=""  # To enable, use "--check"
ANSIBLE_CONFIG="/etc/ansible/ansible-nocache.cfg"
ANSIBLEDEBUG="--skip-tags nodebug"  # To enable, use "--skip-tags debug"
# For On-premise, use one of:
INVENTORY="environments/${ANSIBLE_ENV}/${INVENTORY_OS}-inventory"
# INVENTORY="environments/${ANSIBLE_ENV}/${BUSINESS_REGION}-${INVENTORY_OS}-inventory"
# FOR AWS, use:
# INVENTORY="environments/${ANSIBLE_ENV}/${BUSINESS_REGION_UPPER}_aws_ec2.yml"
PLAYBOOK="playbooks/${ANSIBLE_ENV}/${INVENTORY_OS}-${JOB_BASE_NAME}.yml"
LIMIT_HOST=""  # To enable use "--limit localhost,${TARGETED_HOST}"
VERBOSE=""  # To enable, use "-vvvv"
# Docker
DOCKER_IMG="ansible"
DOCKER_TAG="master"
EXEC_NAME="ansible-playbook-${JOB_BASE_NAME}-${BUILD_NUMBER}"

# Pull in variables stored locally
source .env || true
# Launch container
docker pull ${DOCKER_IMG}:${DOCKER_TAG}
docker run --rm -i \
  -e ANSIBLE_SSH_PRIVATE_KEY="${ANSIBLE_SSH_PRIVATE_KEY}" \
  -e ANSIBLE_SSH_PUBLIC_KEY="${ANSIBLE_SSH_PUBLIC_KEY}" \
  -e ANSIBLE_CONFIG=${ANSIBLE_CONFIG} \
  -e AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \
  -e AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \
  -e DATADOG_API_KEY=${DATADOG_API_KEY} \
  -e INVENTORY="${INVENTORY}" \
  -e PLAYBOOK="${PLAYBOOK}" \
  -e BUILD_NUMBER="${BUILD_NUMBER}" \
  -e JOB_BASE_NAME="${JOB_BASE_NAME}" \
  -e BUILD_CAUSE="${BUILD_CAUSE}" \
  -e BUILD_USER_ID="${BUILD_USER_ID}" \
  -e DOCKER_TAG="${DOCKER_TAG}" \
  -e TARGETED_ENV="${TARGETED_ENV}" \
  -e TARGETED_FUNCTION="${TARGETED_FUNCTION}" \
  -e TARGETED_STACK="${TARGETED_STACK}" \
  -e LIMIT_HOST="${LIMIT_HOST}" \
  -e VERBOSE="${VERBOSE}" \
  -e ANSIBLEDEBUG="${ANSIBLEDEBUG}" \
  -e ANSIBLECHECKMODE="${ANSIBLECHECKMODE}" \
  --name "${EXEC_NAME}" \
  ${DOCKER_IMG}:${DOCKER_TAG} /etc/ansible/scripts/playbook_helper.sh
