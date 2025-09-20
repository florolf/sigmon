#!/bin/bash

set -ueo pipefail

if [[ -f ./hook_cfg.sh ]]
then
	source ./hook_cfg.sh
fi

if [[ -n "${KEY_ATTR_email_address+x}" ]]
then
	EMAIL_ADDRESS="$KEY_ATTR_email_address"
fi

if [[ -z "${EMAIL_ADDRESS+x}" ]]
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

(
	cat <<EOF
Log: ${LOG_ENDPOINT}
Leaf index: ${LEAF_INDEX}
Keyhash: ${KEY_HASH}
Checksum: ${LEAF_CHECKSUM}
EOF

	for hook in "${!LEAF_INFO_@}"
	do
		echo
		echo "Auxiliary leaf info (${hook:10}):"
		echo "------------------------------------------------------------------------"
		echo "${!hook}"
		echo "------------------------------------------------------------------------"
	done
) | mail -s "New ${is_valid}signature from \"${key_name}\" on ${LOG_ENDPOINT} (index ${LEAF_INDEX})" "$EMAIL_ADDRESS"
