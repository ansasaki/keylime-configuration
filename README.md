# keylime-configuration
Configuration options for Keylime

# Agent configuration

## [agent] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|contact_ip|KEYLIME_AGENT_CONTACT_IP|127.0.0.1|
|contact_port|KEYLIME_AGENT_CONTACT_PORT|9002|
|dec_payload_file|KEYLIME_AGENT_DEC_PAYLOAD_FILE|decrypted_payload|
|ek_handle|KEYLIME_AGENT_EK_HANDLE|generate|
|enable_agent_mtls|KEYLIME_AGENT_ENABLE_AGENT_MTLS|true|
|enable_insecure_payload|KEYLIME_AGENT_ENABLE_INSECURE_PAYLOAD|false|
|enable_revocation_notifications|KEYLIME_AGENT_ENABLE_REVOCATION_NOTIFICATIONS|true|
|enc_keyname|KEYLIME_AGENT_ENC_KEYNAME|derived_tci_key|
|exponential_backoff|KEYLIME_AGENT_EXPONENTIAL_BACKOFF|true|
|extract_payload_zip|KEYLIME_AGENT_EXTRACT_PAYLOAD_ZIP|true|
|ip|KEYLIME_AGENT_IP|127.0.0.1|
|max_retries|KEYLIME_AGENT_MAX_RETRIES|4|
|measure_payload_pcr|KEYLIME_AGENT_MEASURE_PAYLOAD_PCR|-1|
|payload_script|KEYLIME_AGENT_PAYLOAD_SCRIPT|autorun.sh|
|port|KEYLIME_AGENT_PORT|9002|
|registrar_ip|KEYLIME_AGENT_REGISTRAR_IP|127.0.0.1|
|registrar_port|KEYLIME_AGENT_REGISTRAR_PORT|8890|
|retry_interval|KEYLIME_AGENT_RETRY_INTERVAL|2|
|revocation_actions|KEYLIME_AGENT_REVOCATION_ACTIONS|[]|
|revocation_cert|KEYLIME_AGENT_REVOCATION_CERT|default|
|revocation_notification_ip|KEYLIME_AGENT_REVOCATION_NOTIFICATION_IP|127.0.0.1|
|revocation_notification_port|KEYLIME_AGENT_REVOCATION_NOTIFICATION_PORT|8992|
|run_as|KEYLIME_AGENT_RUN_AS|keylime:tss|
|secure_size|KEYLIME_AGENT_SECURE_SIZE|1m|
|server_cert|KEYLIME_AGENT_SERVER_CERT|default|
|server_key_password|KEYLIME_AGENT_SERVER_KEY_PASSWORD||
|server_key|KEYLIME_AGENT_SERVER_KEY|default|
|tls_dir|KEYLIME_AGENT_TLS_DIR|default|
|tpm_encryption_alg|KEYLIME_AGENT_TPM_ENCRYPTION_ALG|rsa|
|tpm_hash_alg|KEYLIME_AGENT_TPM_HASH_ALG|sha256|
|tpm_ownerpassword|KEYLIME_AGENT_TPM_OWNERPASSWORD||
|tpm_signing_alg|KEYLIME_AGENT_TPM_SIGNING_ALG|rsassa|
|trusted_client_ca|KEYLIME_AGENT_TRUSTED_CLIENT_CA|default|
|uuid|KEYLIME_AGENT_UUID|d432fbb3-d2f1-4a97-9ef7-75bd81c00000|
|version|KEYLIME_AGENT_VERSION|2.0|

# Verifier configuration

## [verifier] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|auto_migrate_db|KEYLIME_VERIFIER_AUTO_MIGRATE_DB|True|
|client_cert|KEYLIME_VERIFIER_CLIENT_CERT|default|
|client_key_password|KEYLIME_VERIFIER_CLIENT_KEY_PASSWORD||
|client_key|KEYLIME_VERIFIER_CLIENT_KEY|default|
|database_pool_sz_ovfl|KEYLIME_VERIFIER_DATABASE_POOL_SZ_OVFL|5,10|
|database_url|KEYLIME_VERIFIER_DATABASE_URL|sqlite|
|durable_attestation_import|KEYLIME_VERIFIER_DURABLE_ATTESTATION_IMPORT||
|enable_agent_mtls|KEYLIME_VERIFIER_ENABLE_AGENT_MTLS|True|
|exponential_backoff|KEYLIME_VERIFIER_EXPONENTIAL_BACKOFF|True|
|ignore_tomtou_errors|KEYLIME_VERIFIER_IGNORE_TOMTOU_ERRORS|False|
|ip|KEYLIME_VERIFIER_IP|127.0.0.1|
|max_retries|KEYLIME_VERIFIER_MAX_RETRIES|5|
|max_upload_size|KEYLIME_VERIFIER_MAX_UPLOAD_SIZE|104857600|
|measured_boot_evaluate|KEYLIME_VERIFIER_MEASURED_BOOT_EVALUATE|once|
|measured_boot_imports|KEYLIME_VERIFIER_MEASURED_BOOT_IMPORTS|[]|
|measured_boot_policy_name|KEYLIME_VERIFIER_MEASURED_BOOT_POLICY_NAME|accept-all|
|num_workers|KEYLIME_VERIFIER_NUM_WORKERS|0|
|persistent_store_encoding|KEYLIME_VERIFIER_PERSISTENT_STORE_ENCODING||
|persistent_store_format|KEYLIME_VERIFIER_PERSISTENT_STORE_FORMAT|json|
|persistent_store_url|KEYLIME_VERIFIER_PERSISTENT_STORE_URL||
|port|KEYLIME_VERIFIER_PORT|8881|
|quote_interval|KEYLIME_VERIFIER_QUOTE_INTERVAL|2|
|registrar_ip|KEYLIME_VERIFIER_REGISTRAR_IP|127.0.0.1|
|registrar_port|KEYLIME_VERIFIER_REGISTRAR_PORT|8891|
|request_timeout|KEYLIME_VERIFIER_REQUEST_TIMEOUT|60.0|
|require_allow_list_signatures|KEYLIME_VERIFIER_REQUIRE_ALLOW_LIST_SIGNATURES|True|
|retry_interval|KEYLIME_VERIFIER_RETRY_INTERVAL|2|
|server_cert|KEYLIME_VERIFIER_SERVER_CERT|default|
|server_key_password|KEYLIME_VERIFIER_SERVER_KEY_PASSWORD||
|server_key|KEYLIME_VERIFIER_SERVER_KEY|default|
|severity_labels|KEYLIME_VERIFIER_SEVERITY_LABELS|["info", "notice", "warning", "error", "critical", "alert", "emergency"]|
|severity_policy|KEYLIME_VERIFIER_SEVERITY_POLICY|[{"event_id": ".*", "severity_label" : "emergency"}]|
|signed_attributes|KEYLIME_VERIFIER_SIGNED_ATTRIBUTES||
|time_stamp_authority_certs_path|KEYLIME_VERIFIER_TIME_STAMP_AUTHORITY_CERTS_PATH||
|time_stamp_authority_url|KEYLIME_VERIFIER_TIME_STAMP_AUTHORITY_URL||
|tls_dir|KEYLIME_VERIFIER_TLS_DIR|generate|
|transparency_log_sign_algo|KEYLIME_VERIFIER_TRANSPARENCY_LOG_SIGN_ALGO|sha256|
|transparency_log_url|KEYLIME_VERIFIER_TRANSPARENCY_LOG_URL||
|trusted_client_ca|KEYLIME_VERIFIER_TRUSTED_CLIENT_CA|default|
|trusted_server_ca|KEYLIME_VERIFIER_TRUSTED_SERVER_CA|default|
|uuid|KEYLIME_VERIFIER_UUID|default|
|version|KEYLIME_VERIFIER_VERSION|2.0|

### [revocations] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|enabled_revocation_notifications|KEYLIME_VERIFIER_REVOCATIONS_ENABLED_REVOCATION_NOTIFICATIONS|[agent]|
|webhook_url|KEYLIME_VERIFIER_REVOCATIONS_WEBHOOK_URL||
|zmq_ip|KEYLIME_VERIFIER_REVOCATIONS_ZMQ_IP|127.0.0.1|
|zmq_port|KEYLIME_VERIFIER_REVOCATIONS_ZMQ_PORT|8992|

# Tenant configuration

## [tenant] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|accept_tpm_encryption_algs|KEYLIME_TENANT_ACCEPT_TPM_ENCRYPTION_ALGS|ecc, rsa|
|accept_tpm_hash_algs|KEYLIME_TENANT_ACCEPT_TPM_HASH_ALGS|sha512, sha384, sha256|
|accept_tpm_signing_algs|KEYLIME_TENANT_ACCEPT_TPM_SIGNING_ALGS|ecschnorr, rsassa|
|client_cert|KEYLIME_TENANT_CLIENT_CERT|default|
|client_key_password|KEYLIME_TENANT_CLIENT_KEY_PASSWORD||
|client_key|KEYLIME_TENANT_CLIENT_KEY|default|
|ek_check_script|KEYLIME_TENANT_EK_CHECK_SCRIPT||
|enable_agent_mtls|KEYLIME_TENANT_ENABLE_AGENT_MTLS|True|
|exponential_backoff|KEYLIME_TENANT_EXPONENTIAL_BACKOFF|True|
|max_payload_size|KEYLIME_TENANT_MAX_PAYLOAD_SIZE|1048576|
|max_retries|KEYLIME_TENANT_MAX_RETRIES|5|
|mb_refstate|KEYLIME_TENANT_MB_REFSTATE||
|registrar_ip|KEYLIME_TENANT_REGISTRAR_IP|127.0.0.1|
|registrar_port|KEYLIME_TENANT_REGISTRAR_PORT|8891|
|request_timeout|KEYLIME_TENANT_REQUEST_TIMEOUT|60|
|require_ek_cert|KEYLIME_TENANT_REQUIRE_EK_CERT|True|
|retry_interval|KEYLIME_TENANT_RETRY_INTERVAL|2|
|tls_dir|KEYLIME_TENANT_TLS_DIR|default|
|tpm_cert_store|KEYLIME_TENANT_TPM_CERT_STORE|/var/lib/keylime/tpm_cert_store|
|trusted_server_ca|KEYLIME_TENANT_TRUSTED_SERVER_CA|default|
|verifier_ip|KEYLIME_TENANT_VERIFIER_IP|127.0.0.1|
|verifier_port|KEYLIME_TENANT_VERIFIER_PORT|8881|
|version|KEYLIME_TENANT_VERSION|2.0|

# Registrar configuration

## [registrar] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|auto_migrate_db|KEYLIME_REGISTRAR_AUTO_MIGRATE_DB|True|
|database_pool_sz_ovfl|KEYLIME_REGISTRAR_DATABASE_POOL_SZ_OVFL|5,10|
|database_url|KEYLIME_REGISTRAR_DATABASE_URL|sqlite|
|durable_attestation_import|KEYLIME_REGISTRAR_DURABLE_ATTESTATION_IMPORT||
|ip|KEYLIME_REGISTRAR_IP|127.0.0.1|
|persistent_store_encoding|KEYLIME_REGISTRAR_PERSISTENT_STORE_ENCODING||
|persistent_store_format|KEYLIME_REGISTRAR_PERSISTENT_STORE_FORMAT|json|
|persistent_store_url|KEYLIME_REGISTRAR_PERSISTENT_STORE_URL||
|port|KEYLIME_REGISTRAR_PORT|8890|
|prov_db_filename|KEYLIME_REGISTRAR_PROV_DB_FILENAME|provider_reg_data.sqlite|
|server_cert|KEYLIME_REGISTRAR_SERVER_CERT|default|
|server_key_password|KEYLIME_REGISTRAR_SERVER_KEY_PASSWORD||
|server_key|KEYLIME_REGISTRAR_SERVER_KEY|default|
|signed_attributes|KEYLIME_REGISTRAR_SIGNED_ATTRIBUTES|ek_tpm,aik_tpm,ekcert|
|time_stamp_authority_certs_path|KEYLIME_REGISTRAR_TIME_STAMP_AUTHORITY_CERTS_PATH||
|time_stamp_authority_url|KEYLIME_REGISTRAR_TIME_STAMP_AUTHORITY_URL||
|tls_dir|KEYLIME_REGISTRAR_TLS_DIR|default|
|tls_port|KEYLIME_REGISTRAR_TLS_PORT|8891|
|transparency_log_sign_algo|KEYLIME_REGISTRAR_TRANSPARENCY_LOG_SIGN_ALGO|sha256|
|transparency_log_url|KEYLIME_REGISTRAR_TRANSPARENCY_LOG_URL||
|trusted_client_ca|KEYLIME_REGISTRAR_TRUSTED_CLIENT_CA|default|
|version|KEYLIME_REGISTRAR_VERSION|2.0|

# CA configuration

## [ca] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|cert_bits|KEYLIME_CA_CERT_BITS|2048|
|cert_ca_lifetime|KEYLIME_CA_CERT_CA_LIFETIME|3650|
|cert_ca_name|KEYLIME_CA_CERT_CA_NAME|Keylime Certificate Authority|
|cert_country|KEYLIME_CA_CERT_COUNTRY|US|
|cert_crl_dist|KEYLIME_CA_CERT_CRL_DIST|http://localhost:38080/crl|
|cert_lifetime|KEYLIME_CA_CERT_LIFETIME|365|
|cert_locality|KEYLIME_CA_CERT_LOCALITY|Lexington|
|cert_org_unit|KEYLIME_CA_CERT_ORG_UNIT|53|
|cert_organization|KEYLIME_CA_CERT_ORGANIZATION|MITLL|
|cert_state|KEYLIME_CA_CERT_STATE|MA|
|password|KEYLIME_CA_PASSWORD|default|
|version|KEYLIME_CA_VERSION|2.0|

# Logging configuration

## [logging] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|version|KEYLIME_LOGGING_VERSION|2.0|

### [loggers] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|keys|KEYLIME_LOGGING_LOGGERS_KEYS|root,keylime|

### [handlers] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|keys|KEYLIME_LOGGING_HANDLERS_KEYS|consoleHandler|

### [formatters] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|keys|KEYLIME_LOGGING_FORMATTERS_KEYS|formatter|

### [formatter_formatter] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|datefmt|KEYLIME_LOGGING_FORMATTER_FORMATTER_DATEFMT|%Y-%m-%d %H:%M:%S|
|format|KEYLIME_LOGGING_FORMATTER_FORMATTER_FORMAT|%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s|

### [logger_root] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|handlers|KEYLIME_LOGGING_LOGGER_ROOT_HANDLERS|consoleHandler|
|level|KEYLIME_LOGGING_LOGGER_ROOT_LEVEL|INFO|

### [handler_consoleHandler] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|args|KEYLIME_LOGGING_HANDLER_CONSOLEHANDLER_ARGS|(sys.stdout,)|
|class|KEYLIME_LOGGING_HANDLER_CONSOLEHANDLER_CLASS|StreamHandler|
|formatter|KEYLIME_LOGGING_HANDLER_CONSOLEHANDLER_FORMATTER|formatter|
|level|KEYLIME_LOGGING_HANDLER_CONSOLEHANDLER_LEVEL|INFO|

### [logger_keylime] section

|configuration option|environment variable|default value|
|--------------------|--------------------|-------------|
|handlers|KEYLIME_LOGGING_LOGGER_KEYLIME_HANDLERS||
|level|KEYLIME_LOGGING_LOGGER_KEYLIME_LEVEL|INFO|
|qualname|KEYLIME_LOGGING_LOGGER_KEYLIME_QUALNAME|keylime|

