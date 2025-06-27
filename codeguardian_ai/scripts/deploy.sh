#!/bin/bash

# CodeGuardian AI v3.0.0 Enterprise - Production Deployment Script
# Automated deployment script for Kubernetes production environment

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NAMESPACE="codeguardian"
MONITORING_NAMESPACE="monitoring"
IMAGE_TAG="${IMAGE_TAG:-v3.0.0}"
REGISTRY="${REGISTRY:-codeguardian}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Error handling
error_exit() {
    log_error "$1"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        error_exit "kubectl is not installed or not in PATH"
    fi
    
    # Check if docker is installed
    if ! command -v docker &> /dev/null; then
        error_exit "docker is not installed or not in PATH"
    fi
    
    # Check if helm is installed
    if ! command -v helm &> /dev/null; then
        error_exit "helm is not installed or not in PATH"
    fi
    
    # Check kubectl connection
    if ! kubectl cluster-info &> /dev/null; then
        error_exit "Cannot connect to Kubernetes cluster"
    fi
    
    log_success "Prerequisites check passed"
}

# Build Docker image
build_image() {
    log_info "Building Docker image..."
    
    cd "$PROJECT_ROOT"
    
    # Build production image
    docker build \
        -f Dockerfile.production \
        -t "${REGISTRY}/api:${IMAGE_TAG}" \
        -t "${REGISTRY}/api:latest" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg VERSION="${IMAGE_TAG}" \
        --build-arg VCS_REF="$(git rev-parse HEAD)" \
        .
    
    log_success "Docker image built successfully"
}

# Push Docker image
push_image() {
    log_info "Pushing Docker image to registry..."
    
    # Login to registry if credentials are provided
    if [[ -n "${DOCKER_USERNAME:-}" && -n "${DOCKER_PASSWORD:-}" ]]; then
        echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
    fi
    
    # Push images
    docker push "${REGISTRY}/api:${IMAGE_TAG}"
    docker push "${REGISTRY}/api:latest"
    
    log_success "Docker image pushed successfully"
}

# Create namespaces
create_namespaces() {
    log_info "Creating namespaces..."
    
    # Create codeguardian namespace
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Create monitoring namespace
    kubectl create namespace "$MONITORING_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Label namespaces
    kubectl label namespace "$NAMESPACE" environment="$ENVIRONMENT" --overwrite
    kubectl label namespace "$MONITORING_NAMESPACE" environment="$ENVIRONMENT" --overwrite
    
    log_success "Namespaces created successfully"
}

# Deploy secrets
deploy_secrets() {
    log_info "Deploying secrets..."
    
    # Check if secrets exist
    if [[ -z "${JWT_SECRET_KEY:-}" ]]; then
        log_warning "JWT_SECRET_KEY not provided, generating random key"
        JWT_SECRET_KEY=$(openssl rand -base64 32)
    fi
    
    if [[ -z "${DATABASE_PASSWORD:-}" ]]; then
        log_warning "DATABASE_PASSWORD not provided, generating random password"
        DATABASE_PASSWORD=$(openssl rand -base64 16)
    fi
    
    if [[ -z "${REDIS_PASSWORD:-}" ]]; then
        log_warning "REDIS_PASSWORD not provided, generating random password"
        REDIS_PASSWORD=$(openssl rand -base64 16)
    fi
    
    if [[ -z "${API_KEY:-}" ]]; then
        log_warning "API_KEY not provided, generating random key"
        API_KEY=$(openssl rand -base64 32)
    fi
    
    # Create secret
    kubectl create secret generic codeguardian-secrets \
        --namespace="$NAMESPACE" \
        --from-literal=JWT_SECRET_KEY="$JWT_SECRET_KEY" \
        --from-literal=DATABASE_PASSWORD="$DATABASE_PASSWORD" \
        --from-literal=REDIS_PASSWORD="$REDIS_PASSWORD" \
        --from-literal=API_KEY="$API_KEY" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    log_success "Secrets deployed successfully"
}

# Deploy infrastructure
deploy_infrastructure() {
    log_info "Deploying infrastructure components..."
    
    # Apply production deployment
    kubectl apply -f "$PROJECT_ROOT/infrastructure/kubernetes/production-deployment.yaml"
    
    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL to be ready..."
    kubectl wait --for=condition=ready pod -l app=postgres -n "$NAMESPACE" --timeout=300s
    
    # Wait for Redis to be ready
    log_info "Waiting for Redis to be ready..."
    kubectl wait --for=condition=ready pod -l app=redis -n "$NAMESPACE" --timeout=300s
    
    log_success "Infrastructure deployed successfully"
}

# Deploy application
deploy_application() {
    log_info "Deploying CodeGuardian API..."
    
    # Update image in deployment
    kubectl set image deployment/codeguardian-api \
        api="${REGISTRY}/api:${IMAGE_TAG}" \
        -n "$NAMESPACE"
    
    # Wait for deployment to be ready
    log_info "Waiting for application deployment to be ready..."
    kubectl rollout status deployment/codeguardian-api -n "$NAMESPACE" --timeout=600s
    
    # Verify pods are running
    kubectl get pods -n "$NAMESPACE" -l app=codeguardian
    
    log_success "Application deployed successfully"
}

# Deploy monitoring
deploy_monitoring() {
    log_info "Deploying monitoring stack..."
    
    # Apply monitoring stack
    kubectl apply -f "$PROJECT_ROOT/infrastructure/kubernetes/monitoring-stack.yaml"
    
    # Wait for Prometheus to be ready
    log_info "Waiting for Prometheus to be ready..."
    kubectl wait --for=condition=ready pod -l app=prometheus -n "$MONITORING_NAMESPACE" --timeout=300s
    
    # Wait for Grafana to be ready
    log_info "Waiting for Grafana to be ready..."
    kubectl wait --for=condition=ready pod -l app=grafana -n "$MONITORING_NAMESPACE" --timeout=300s
    
    log_success "Monitoring stack deployed successfully"
}

# Run health checks
run_health_checks() {
    log_info "Running health checks..."
    
    # Get service endpoint
    SERVICE_IP=$(kubectl get service codeguardian-service -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    
    if [[ -z "$SERVICE_IP" ]]; then
        SERVICE_IP=$(kubectl get service codeguardian-service -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
    fi
    
    if [[ -z "$SERVICE_IP" ]]; then
        log_warning "LoadBalancer IP/hostname not available yet, using port-forward for health check"
        kubectl port-forward service/codeguardian-service 8080:80 -n "$NAMESPACE" &
        PORT_FORWARD_PID=$!
        sleep 5
        SERVICE_URL="http://localhost:8080"
    else
        SERVICE_URL="http://$SERVICE_IP"
    fi
    
    # Health check
    log_info "Checking application health..."
    for i in {1..30}; do
        if curl -f "$SERVICE_URL/health" &> /dev/null; then
            log_success "Health check passed"
            break
        else
            log_info "Health check attempt $i/30 failed, retrying in 10 seconds..."
            sleep 10
        fi
        
        if [[ $i -eq 30 ]]; then
            error_exit "Health check failed after 30 attempts"
        fi
    done
    
    # Kill port-forward if used
    if [[ -n "${PORT_FORWARD_PID:-}" ]]; then
        kill $PORT_FORWARD_PID &> /dev/null || true
    fi
    
    # Test API endpoint
    log_info "Testing API endpoint..."
    if [[ -n "$SERVICE_IP" ]]; then
        curl -s "$SERVICE_URL/api/v3/status" | jq .
    fi
    
    log_success "Health checks completed successfully"
}

# Display deployment information
display_info() {
    log_info "Deployment completed successfully!"
    echo
    echo "=== Deployment Information ==="
    echo "Environment: $ENVIRONMENT"
    echo "Image: ${REGISTRY}/api:${IMAGE_TAG}"
    echo "Namespace: $NAMESPACE"
    echo
    
    # Get service information
    echo "=== Service Information ==="
    kubectl get services -n "$NAMESPACE"
    echo
    
    # Get pod information
    echo "=== Pod Information ==="
    kubectl get pods -n "$NAMESPACE"
    echo
    
    # Get ingress information
    echo "=== Ingress Information ==="
    kubectl get ingress -n "$NAMESPACE"
    echo
    
    # Get monitoring information
    echo "=== Monitoring Information ==="
    kubectl get services -n "$MONITORING_NAMESPACE"
    echo
    
    log_success "CodeGuardian AI v3.0.0 Enterprise deployed successfully!"
}

# Rollback function
rollback() {
    log_warning "Rolling back deployment..."
    
    kubectl rollout undo deployment/codeguardian-api -n "$NAMESPACE"
    kubectl rollout status deployment/codeguardian-api -n "$NAMESPACE"
    
    log_success "Rollback completed"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up resources..."
    
    # Delete deployments
    kubectl delete -f "$PROJECT_ROOT/infrastructure/kubernetes/production-deployment.yaml" --ignore-not-found=true
    kubectl delete -f "$PROJECT_ROOT/infrastructure/kubernetes/monitoring-stack.yaml" --ignore-not-found=true
    
    # Delete namespaces
    kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
    kubectl delete namespace "$MONITORING_NAMESPACE" --ignore-not-found=true
    
    log_success "Cleanup completed"
}

# Main deployment function
main() {
    local action="${1:-deploy}"
    
    case "$action" in
        "deploy")
            log_info "Starting CodeGuardian AI v3.0.0 Enterprise deployment..."
            check_prerequisites
            build_image
            push_image
            create_namespaces
            deploy_secrets
            deploy_infrastructure
            deploy_application
            deploy_monitoring
            run_health_checks
            display_info
            ;;
        "rollback")
            rollback
            ;;
        "cleanup")
            cleanup
            ;;
        "health-check")
            run_health_checks
            ;;
        *)
            echo "Usage: $0 {deploy|rollback|cleanup|health-check}"
            echo
            echo "Commands:"
            echo "  deploy      - Deploy the complete application stack"
            echo "  rollback    - Rollback to previous deployment"
            echo "  cleanup     - Remove all deployed resources"
            echo "  health-check - Run health checks on deployed application"
            exit 1
            ;;
    esac
}

# Handle script interruption
trap 'log_error "Script interrupted"; exit 1' INT TERM

# Run main function
main "$@"

