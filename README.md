# Ansible ECS Launcher
This script collection enables you to run Ansible in Fargate/ECS with configurable CPU/MEM.

# start-ecs.py
This is the script that should be run by CI/CD (i.e., Jenkins). It uses Cloudwatch log streaming to replay Fargate ECS logs to Jenkins console.

# start-local.sh
Run Ansible locally, used for testing and development.

# credential_helper.sh
This script runs inside the container at execution. Depending on how you build your container, you may be using a certificate in the container.
Alternatively, you can pass SSM Parameters to the workspace using Jenkins (preferred). This script will use one or the other.

# playbook_helper.sh
This is the script that should be executed by the Fargate task at launch.

Required environment variables:
```bash
# SSH keys for connecting to Linux machines
ANSIBLE_SSH_PRIVATE_KEY=
ANSIBLE_SSH_PUBLIC_KEY=
# AWS credentials for target AWS account
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
# Setup for environment per AWS account
INVENTORY='environments/{account_alias}/AMER_aws_ec2.yml'
# Example Ansible playbook
PLAYBOOK='playbooks/{account_alias}/ubuntu-validation.yml'
```

Optional environment variables:
```bash
# Optional, used within Ansible to target AWS resources
ENVIRONMENT=
VARIANT=
REGION=
VERSION=
# Optional, used within Ansible to reference Jenkins actions
BUILD_NUMBER=
JOB_BASE_NAME=
JOB_NAME=
BUILD_CAUSE=
BUILD_USER_ID=
DOCKER_TAG=
# Optional, used within Ansible to target AWS resources
TARGETED_ENV=
TARGETED_FUNCTION=
TARGETED_STACK=
# Ansible check mode
ANSIBLECHECKMODE=
# Optional, used to change cache config at runtime
ANSIBLE_CONFIG=
# Optional, I use 'debug' tags to enable verbosity in tasks and skip them by default
ANSIBLEDEBUG='--skip-tags debug',
# Optional, used within Ansible to target AWS resources
BUSINESS_REGION=
# Optional, used by Jenkins to limit hosts by inventory name (parameter builds)
LIMIT_HOST=
# Ansible verbosity
VERBOSE=
# Fargate ECS overrides
FARGATE_CPU=
FARGATE_MEMORY=
```
