#!/usr/bin/env bash
set -e

##set ANSI escaape codes
NC='\033[0m'
RED='\033[1;31m'
GRN='\033[1;32m'
BLU='\033[1;36m'

#executes a series of terraform, az cli, and kubernetes commands to deploy or destroy an example crs architecture

echo -e "${BLU}Applying environment variables from ./env${NC}"
# shellcheck disable=SC1094
source ./env
echo -e "${GRN}Current azure account status:${NC}"
az account show --query "{SubscriptionID:id, Tenant:tenantId}" --output table

if [ "$LOCAL_TEST" = "ON" ]; then
    export TF_VAR_capi_node_count=1
fi

if [ "$LITELLM_REPLICA" != "" ]; then
    export TF_VAR_litellm_node_count=$LITELLM_REPLICA
fi

if [ "$TEST_ROUND" == "" ]; then
    export TEST_ROUND="False"
fi

#deploy the AKS cluster and kubernetes resources function
up() {

	echo -e "${BLU}Applying environment variables to yaml from templates${NC}"
	CLIENT_BASE64=$(echo -n "$TF_VAR_ARM_CLIENT_SECRET" | base64)
	CRS_KEY_BASE64=$(echo -n "$CRS_KEY_TOKEN" | base64)
	COMPETITION_API_KEY_BASE64=$(echo -n "$COMPETITION_API_KEY_TOKEN" | base64)
	export CLIENT_BASE64
	export CRS_KEY_BASE64
	export COMPETITION_API_KEY_BASE64
	export TS_DNS_IP
	envsubst <k8s/base/tailscale-operator/operator.template >k8s/base/tailscale-operator/operator.yaml

	#deploy AKS resources in Azure
	echo -e "${BLU}Deploying AKS cluster Resources${NC}"
	terraform init \
	  -backend-config="resource_group_name=${BACKEND_RESOURCE_GROUP_NAME:-teamatlanta-tfstate-rg}" \
	  -backend-config="storage_account_name=${BACKEND_STORAGE_ACCOUNT_NAME:-teamatlantatfstate}" \
	  -backend-config="container_name=${BACKEND_CONTAINER_NAME:-tfstate}" \
	  -backend-config="key=${BACKEND_KEY:-terraform.tfstate}" \
	  -backend-config="subscription_id=${TF_VAR_ARM_SUBSCRIPTION_ID}"
	terraform apply -auto-approve

	#set resource group name and kubernetes cluster name variables from terraform outputs

	KUBERNETES_CLUSTER_NAME=$(terraform output -raw kubernetes_cluster_name)
	RESOURCE_GROUP_NAME=$(terraform output -raw resource_group_name)

	echo -e "${GRN}KUBERNETES_CLUSTER_NAME is $KUBERNETES_CLUSTER_NAME"
	echo "RESOURCE_GROUP_NAME is $RESOURCE_GROUP_NAME${NC}"
	echo -e "${BLU}Retrieving credentials to access AKS cluster${NC}"
	#retrieve credentials to access AKS cluster

	az aks get-credentials --resource-group "$RESOURCE_GROUP_NAME" --name "$KUBERNETES_CLUSTER_NAME"

	if [ "$LOCAL_TEST" = "ON" ]; then
		# COMPETITION SERVER
		export COMPETITION_URL="http://competition-server.competition-server.svc.cluster.local:1323"
		envsubst <k8s/base/competition-server/.dockerconfigjson.template >k8s/base/competition-server/.dockerconfigjson
		envsubst <k8s/base/competition-server/deployment.template >k8s/base/competition-server/deployment.yaml
		kubectl apply -k k8s/base/competition-server/
	fi

	export KUBERNETES_CLUSTER_NAME 
	export RESOURCE_GROUP_NAME
	envsubst <k8s/base/crs-webservice/ingress.template >k8s/base/crs-webservice/ingress.yaml
	envsubst <k8s/base/crs-webservice/.dockerconfigjson.template >k8s/base/crs-webservice/.dockerconfigjson
	envsubst <k8s/base/crs-webservice/secrets.template >k8s/base/crs-webservice/secrets.yaml
	envsubst <k8s/base/crs-webservice/deployment.template >k8s/base/crs-webservice/deployment.yaml
    for litellm in multilang user-java patch; do
        export LITELLM_NAME=$litellm
        if [ $litellm == "user-java" ]; then
            export ANTHROPIC_BUDGET_LIMIT="$ANTHROPIC_BUDGET_LIMIT_user_java"
            export SONNET4_TPM="$SONNET4_TPM_user_java"
            export OPUS4_TPM="$OPUS4_TPM_user_java"
        else
            key="ANTHROPIC_BUDGET_LIMIT_$litellm"
            export ANTHROPIC_BUDGET_LIMIT="${!key}"
            key="SONNET4_TPM_$litellm"
            export SONNET4_TPM="${!key}"
            key="OPUS4_TPM_$litellm"
            export OPUS4_TPM="${!key}"
        fi
        if [ $litellm == "patch" ]; then
            export LITELLM_REPLICA=$LITELLM_REPLICA_PATCH
        else
            export LITELLM_REPLICA=$LITELLM_REPLICA_BUG_FINDING
        fi
        if [ $ANTHROPIC_BUDGET_LIMIT == "" ]; then
            echo "ANTHROPIC_BUDGET_LIMIT_multilang is required (recommend \"5000\")"
            echo "ANTHROPIC_BUDGET_LIMIT_user_java is required (recommend \"5000\")"
            echo "ANTHROPIC_BUDGET_LIMIT_patch is required (recommend \"5000\")"
            exit -1
        fi

        if [ $SONNET4_TPM == "" ]; then
            echo "SONNET4_TPM_multilang is required (recommend \"200000\")"
            echo "SONNET4_TPM_user_java is required (recommend \"200000\")"
            echo "SONNET4_TPM_patch is required (recommend \"200000\")"
            exit -1
        fi
        
        if [ $OPUS4_TPM == "" ]; then
            echo "OPUS4_TPM_multilang is required (recommend \"200000\")"
            echo "OPUS4_TPM_user_java is required (recommend \"200000\")"
            echo "OPUS4_TPM_patch is required (recommend \"200000\")"
            exit -1
        fi

        if [ $LITELLM_REPLICA == "" ]; then
            echo "LITELLM_REPLICA_PATCH and LITELLM_REPLICA_BUG_FINDING are required"
            exit -1
        fi
	    envsubst <k8s/base/crs-webservice/litellm.template >k8s/base/crs-webservice/litellm-$litellm.yaml
        unset LITELLM_NAME
        unset LITELLM_REPLICA
        unset ANTHROPIC_BUDGET_LIMIT
        unset SONNET4_TPM
        unset OPUS4_TPM
    done
    if [ "$AIXCC_OTEL_EXPORTER_OTLP_ENDPOINT" = "" ]; then
        echo -e "${BLU}USE opentelemetry-local!${NC}"
	    envsubst '$AIXCC_OTEL_EXPORTER_OTLP_ENDPOINT $AIXCC_OTEL_EXPORTER_OTLP_HEADERS' <k8s/base/crs-webservice/opentelemetry-local.template >k8s/base/crs-webservice/opentelemetry.yaml
    else
        echo -e "${BLU}USE AIxCC's opentelemetry!${NC}"
	    envsubst '$AIXCC_OTEL_EXPORTER_OTLP_ENDPOINT $AIXCC_OTEL_EXPORTER_OTLP_HEADERS' <k8s/base/crs-webservice/opentelemetry.template >k8s/base/crs-webservice/opentelemetry.yaml
    fi
	unset KUBERNETES_CLUSTER_NAME
	unset RESOURCE_GROUP_NAME

	#deploy kubernetes resources in AKS cluster
	kubectl apply -k k8s/base/tailscale-operator/
	kubectl apply -k k8s/base/tailscale-dns/

	echo -e "${BLU}Waiting for the service nameserver to exist${NC}"
	timeout 5m bash -c "until kubectl get svc -n tailscale nameserver > /dev/null 2>&1; do sleep 1; done" || echo -e "${RED}Error: nameserver failed to exist within 5 minutes${NC}"
	echo -e "${BLU}Waiting for nameserver to have a valid ClusterIP${NC}"
	timeout 5m bash -c "until kubectl get svc -n tailscale nameserver -o jsonpath='{.spec.clusterIP}' | grep -v '<none>' > /dev/null 2>&1; do sleep 1; done" || echo -e "${RED}Error: nameserver failed to obtain a valid CLusterIP within 5 minutes${NC}"
	TS_DNS_IP=$(kubectl get svc -n tailscale nameserver -o jsonpath='{.spec.clusterIP}')
	envsubst <k8s/base/tailscale-coredns/coredns-custom.template >k8s/base/tailscale-coredns/coredns-custom.yaml

	kubectl apply -k k8s/base/tailscale-coredns/
	kubectl apply -k k8s/base/crs-webservice/
    for litellm in multilang user-java patch; do
	    kubectl apply -f k8s/base/crs-webservice/litellm-$litellm.yaml
    done
	kubectl apply -k k8s/base/tailscale-connections/

	echo -e "${BLU}Waiting for ingress hostname DNS registration${NC}"
	timeout 5m bash -c "until kubectl get ingress -n crs-webservice crs-webapp -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' | grep -q '.'; do sleep 1; done" || echo -e "${BLU}Error: Ingress hostname failed to be to set within 5 minutes${NC}"
	INGRESS_HOSTNAME=$(kubectl get ingress -n crs-webservice crs-webapp -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
	echo -e "${GRN}Your ingress DNS hostname is $INGRESS_HOSTNAME${NC}"

}

#destroy the AKS cluster and kubernetes resources function
down() {
	echo -e "${BLU}Deleting Kubernetes resource${NC}"
	set +e
	kubectl delete -k k8s/base/tailscale-connections/
	kubectl delete pods --all -n crs-webservice
	kubectl delete -k k8s/base/crs-webservice/
	timeout 2m bash -c "until kubectl get statefulset -n tailscale -l tailscale.com/parent-resource=crs-webapp,tailscale.com/parent-resource-ns=crs-webservice 2>&1 | grep -q 'No resources found'; do sleep 1; done" || echo -e "${RED}Error: StatefulSet cleanup timed out after 2 minutes${NC}"
	kubectl delete -k k8s/base/tailscale-coredns/
	kubectl delete -k k8s/base/tailscale-dns/
	kubectl delete -k k8s/base/tailscale-operator/
	if [ "$LOCAL_TEST" = "ON" ]; then
		# COMPETITION SERVER 
		kubectl delete -k k8s/base/competition-server/
	fi
	
  	set -e
	echo -e "${BLU}Destroying AKS cluster${NC}"
	terraform apply -destroy -auto-approve

}

case $1 in
up)
	up
	;;
down)
	down
	;;
*)
	echo -e "${RED}The only acceptable arguments are up and down${NC}"
	;;
esac
