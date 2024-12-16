#!/bin/bash
# THIS SCRIPT IS USED BY ECS FOR LAUNCHING TASKS
# Display environment variables
echo "[INFO] AWS Environment Variables:"
echo "  AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:0:5}*****"
echo "  AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY:0:5}*****"
echo "[INFO] Ansible Environment Variables:"
echo "  ANSIBLEDEBUG: ${ANSIBLEDEBUG}"
echo "  ANSIBLECHECKMODE: ${ANSIBLECHECKMODE}"
echo "  BUSINESS_REGION: ${BUSINESS_REGION}"
echo "  DOCKER_TAG: ${DOCKER_TAG}"
echo "  INVENTORY: ${INVENTORY}"
echo "  PLAYBOOK: ${PLAYBOOK}"
echo "  LIMIT_HOST: ${LIMIT_HOST}"
echo "  TARGETED_ENV: ${TARGETED_ENV}"
echo "  TARGETED_FUNCTION: ${TARGETED_FUNCTION}"
echo "  TARGETED_STACK: ${TARGETED_STACK}"
echo "  VERBOSE: ${VERBOSE}"
echo "[INFO] Jenkins Environment Variables:"
echo "  BUILD_CAUSE: ${BUILD_CAUSE}"
echo "  BUILD_NUMBER: ${BUILD_NUMBER}"
echo "  BUILD_USER_ID: ${BUILD_USER_ID}"
echo "  JOB_BASE_NAME: ${JOB_BASE_NAME}"
# Write SSH credentials
echo "[INFO] Running credential helper..."
/etc/ansible/scripts/credential_helper.sh
# Run debugging commands if VERBOSE is set
if [[ ${VERBOSE} == "-vvvv" ]]; then
  echo "[DEBUG] Displaying system information..."
  ansible --version
  ansible-config dump --only-changed
  ansible-galaxy collection list
  uname -a
  cat /etc/os-release
  apt list --installed
  pip3 list
  pip3 show boto boto3 botocore
fi
# Run Playbook
echo "[INFO] Running Ansible Playbook..."
/usr/local/bin/ansible-playbook ${VERBOSE} ${ANSIBLEDEBUG} ${ANSIBLECHECKMODE} --extra-vars "jenkins_build_num=${BUILD_NUMBER} jenkins_base_name=${JOB_BASE_NAME} jenkins_build_cause=${BUILD_CAUSE} jenkins_build_user_id=${BUILD_USER_ID} jenkins_github_branch=${DOCKER_TAG} jenkins_targeted_env=${TARGETED_ENV} jenkins_targeted_func=${TARGETED_FUNCTION} jenkins_targeted_stack=${TARGETED_STACK}" -i ${INVENTORY} ${PLAYBOOK} ${LIMIT_HOST}
