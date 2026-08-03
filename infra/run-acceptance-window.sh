#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:=us-east-1}"
: "${ECS_CLUSTER:?Set ECS_CLUSTER to the stack Cluster output}"
: "${ECS_SERVICE:?Set ECS_SERVICE to the stack ServiceName output}"

cleanup() {
  aws ecs update-service --region "$AWS_REGION" --cluster "$ECS_CLUSTER" --service "$ECS_SERVICE" --desired-count 0 >/dev/null
}

trap cleanup EXIT INT TERM
service_state="$(aws ecs describe-services --region "$AWS_REGION" --cluster "$ECS_CLUSTER" --services "$ECS_SERVICE" --query 'services[0].[desiredCount,runningCount,length(deployments),deployments[0].rolloutState]' --output text)"
if [ "$service_state" != $'0\t0\t1\tCOMPLETED' ]; then
  echo "Refusing to start: the exact service must be idle at desired/running 0 with one completed deployment (got: $service_state)." >&2
  exit 1
fi
aws ecs update-service --region "$AWS_REGION" --cluster "$ECS_CLUSTER" --service "$ECS_SERVICE" --desired-count 1 >/dev/null
aws ecs wait services-stable --region "$AWS_REGION" --cluster "$ECS_CLUSTER" --services "$ECS_SERVICE"
deadline=$(( $(date +%s) + 14400 ))
echo "One acceptance task started. Do not deploy or update the stack during this window. Ctrl-C ends it early; the hard four-hour limit restores desired count 0."
while [ "$(date +%s)" -lt "$deadline" ]; do sleep 60; done
