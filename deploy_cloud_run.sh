#!/usr/bin/env bash
set -e

PROJECT_ID="qwiklabs-gcp-03-fd05546dff54"
REGION="asia-south2"
SERVICE_NAME="soc-swarm-cti"

echo "=========================================="
echo "Deploying SOC Swarm CTI MVP to Cloud Run"
echo "Project: $PROJECT_ID | Region: $REGION"
echo "=========================================="

gcloud run deploy "$SERVICE_NAME" \
  --source . \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --platform managed \
  --allow-unauthenticated \
  --quiet \
  --set-env-vars="GOOGLE_CLOUD_PROJECT=$PROJECT_ID,GOOGLE_CLOUD_LOCATION=global"

echo "=========================================="
echo "Cloud Run Deployment Complete!"
echo "=========================================="
