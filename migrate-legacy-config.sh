#!/bin/bash
# Takes the identity providers, clients and API clients of oidc-demo 2.x over into a 3.x instance that runs in
# Kubernetes (README, "Upgrade from 2.x").
#
#   ./migrate-legacy-config.sh [--context <kube context>] [--namespace <namespace>] [--deployment <name>]
#                              [--container <name>] [--apply]
#
# --context     kube context of the cluster (default: the current context)
# --namespace   namespace of the oidc-demo 3.x deployment (default: the namespace of the context)
# --deployment  name of the oidc-demo 3.x deployment (default: oidc-demo)
# --container   container of oidc-demo in the pod, needed when the pod has sidecars (default: the default container
#               of the pod)
# --apply       saves the import; without it the import is a dry run that shows what would be imported
#
# The URL of the 2.x database is read from the environment variable OLD_DATABASE_URL, or asked for (without echo)
# when it is not set, e.g. postgres://user:password@host:5432/dbname (percent-encode special characters).
#
# How it works: the URL goes through stdin into `kubectl exec` of the 3.x deployment, where
# `manage.py import_legacy_config --from-database` reads the old database with legacy_export.sql and imports it.
# So the 3.x pod must be able to reach the 2.x database, and neither psql nor an export file is needed. The URL
# never appears on a command line, in the pod spec or in a file.
#
# Before: 3.x runs with its own, new database, and the configuration there is still empty (the import refuses to run
# otherwise, e.g. after DJANGO_LOAD_INITIAL_DATA=on).
set -euo pipefail

function usage() {
    echo "Usage: ./migrate-legacy-config.sh [--context <kube context>] [--namespace <namespace>]" \
        "[--deployment <name>] [--container <name>] [--apply]" >&2
    exit 1
}

CONTEXT=""
NAMESPACE=""
DEPLOYMENT=oidc-demo
CONTAINER=""
APPLY=no

while [ $# -gt 0 ]; do
    case "$1" in
        --context|--namespace|--deployment|--container)
            if [ $# -lt 2 ]; then
                echo "$1 needs a value." >&2
                usage
            fi
            case "$1" in
                --context) CONTEXT=$2 ;;
                --namespace) NAMESPACE=$2 ;;
                --deployment) DEPLOYMENT=$2 ;;
                --container) CONTAINER=$2 ;;
            esac
            shift 2
            ;;
        --apply)
            APPLY=yes
            shift
            ;;
        *)
            echo "Unknown argument '$1'." >&2
            usage
            ;;
    esac
done

# The command lines are built as arrays that are never empty: with set -u, the bash 3.2 of macOS stops on
# "${array[@]}" of an empty array.
KUBECTL_COMMAND=(kubectl)
if [ -n "$CONTEXT" ]; then
    KUBECTL_COMMAND+=(--context "$CONTEXT")
fi
if [ -n "$NAMESPACE" ]; then
    KUBECTL_COMMAND+=(--namespace "$NAMESPACE")
fi
# kubectl exec runs in one pod of the deployment; every pod uses the same database, so any of them will do.
KUBECTL_COMMAND+=(exec -i "deployment/$DEPLOYMENT")
if [ -n "$CONTAINER" ]; then
    KUBECTL_COMMAND+=(--container "$CONTAINER")
fi

IMPORT_COMMAND=(python manage.py import_legacy_config --from-database)
if [ "$APPLY" = "no" ]; then
    IMPORT_COMMAND+=(--dry-run)
fi

if [ -z "${OLD_DATABASE_URL:-}" ]; then
    read -r -s -p "URL of the 2.x database (postgres://user:password@host:5432/dbname): " OLD_DATABASE_URL
    echo
fi
if [ -z "$OLD_DATABASE_URL" ]; then
    echo "No URL of the 2.x database was given." >&2
    exit 1
fi

echo "Running: ${KUBECTL_COMMAND[*]} -- ${IMPORT_COMMAND[*]}"
printf '%s\n' "$OLD_DATABASE_URL" | "${KUBECTL_COMMAND[@]}" -- "${IMPORT_COMMAND[@]}"

if [ "$APPLY" = "no" ]; then
    echo "That was a dry run. Run it again with --apply to save the import."
fi
