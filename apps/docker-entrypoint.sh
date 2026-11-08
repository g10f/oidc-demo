#!/usr/bin/env bash
set -xef

# Without SECRET_KEY the server refuses to start, the manage.py commands below would still run with the
# development key. So stop here, before the migration. ${SECRET_KEY:+set} keeps the key out of the trace (set -x).
if [ -z "${SECRET_KEY:+set}" ]; then
  echo "The environment variable SECRET_KEY must be set." >&2
  exit 1
fi

if [ "$DJANGO_MIGRATE" = "on" ]; then
	./manage.py migrate --noinput
fi

if  [ "$DJANGO_CREATE_SUPERUSER" = "on" ] || [ "$DJANGO_LOAD_INITIAL_DATA" = "on"  ]; then
  user_count=$(./manage.py user_count)

  if [[ $user_count -eq 0 ]]; then

    if  [ "$DJANGO_CREATE_SUPERUSER" = "on" ]; then
      ./manage.py createsuperuser --noinput
    fi

    if [ "$DJANGO_LOAD_INITIAL_DATA" = "on" ]; then
      ./manage.py loaddata initial_data
    fi

  fi
fi

exec "$@"
