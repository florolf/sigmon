#!/bin/bash

set -ueo pipefail

if [[ -f ./hook_cfg.sh ]]
then
	source ./hook_cfg.sh
fi

if [[ -n "${KEY_ATTR_pushover_user+x}" ]]
then
	PUSHOVER_USER_TOKEN="$KEY_ATTR_pushover_user"
fi

if [[ -z "${PUSHOVER_USER_TOKEN+x}" ]]
then
	exit 0
fi

key_name="${KEY_ATTR_alias:-$KEY_HASH}"

if [[ "${LEAF_SIGNATURE_VALID+x}" ]]
then
	if [[ "$LEAF_SIGNATURE_VALID" -eq 1 ]]
	then
		is_valid="valid "
	else
		is_valid="INVALID "
	fi
else
	is_valid=""
fi

msg="New ${is_valid}signature at index ${LEAF_INDEX} on ${LOG_ENDPOINT} from ${key_name}, checksum ${LEAF_CHECKSUM}"

curl -s \
  --form-string "token=$PUSHOVER_APP_TOKEN" \
  --form-string "user=$PUSHOVER_USER_TOKEN" \
  --form-string "sound=vibrate" \
  --form-string "priority=1" \
  --form-string "message=$msg" \
  https://api.pushover.net/1/messages.json
