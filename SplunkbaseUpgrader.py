import requests  # type: ignore
import boto3  # type: ignore
import json
import os
import logging
import sys
from botocore.config import Config  # type: ignore

####################################
# Splunkbase Download Script
# Last Updated: 05.09.2025
# Creator: Andrew Burnett
####################################


def sfg_cleanup_exception_handler(subject, message):
    logging.error(f"{subject}: {message}")
    sys.exit()


def get_aws_credentials():
    """Get admin password from AWS Secrets Manager"""
    try:
        client = boto3.client("secretsmanager", region_name="us-east-1")
        sm_response = client.get_secret_value(SecretId="splunk/credentials")
        secrets = json.loads(sm_response["SecretString"])
        return secrets["password"]
    except Exception as e:
        subject = "Trouble Getting Admin Password From Secrets Manager"
        message = f"Error getting token from SecretsManager: {e}"
        sfg_cleanup_exception_handler(subject, message)


def get_splunkbase_credentials():
    """Get Splunkbase credentials from Secrets Manager"""
    username = "admin@gmail.com"  # TODO: Consider making this configurable
    client = boto3.client("secretsmanager", region_name="us-east-1")
    cert_response = client.get_secret_value(SecretId="splunk/manual/Splunkbase")
    secrets = json.loads(cert_response["SecretString"])
    return username, secrets["password"]


def get_session_key(admin_password, hostname, domain):
    """Get Splunk session key"""
    try:
        url = f"https://{hostname}.{domain}:8089"
        response = requests.get(
            f"{url}/servicesNS/admin/search/auth/login",
            data={
                "username": "admin",
                "password": admin_password,
                "output_mode": "json"
            },
            verify=securian_trust,
            timeout=30
        ).text

        if response:
            return json.loads(response)["sessionKey"]
    except Exception as e:
        subject = "Trouble Getting Session Key"
        message = f"Unable to get session key: {e}"
        sfg_cleanup_exception_handler(subject, message)


def authenticate(username, password):
    """Authenticate with Splunkbase and return session cookies"""
    login_url = "https://splunkbase.splunk.com/api/account:login/"
    payload = {
        "username": username,
        "password": password
    }
    response = requests.post(login_url, data=payload)
    if response.status_code == 200:
        return response.cookies.get_dict()
    raise Exception(f"Authentication failed with status code: {response.status_code}")


def get_apps_list(session_key, hostname, domain):
    """Retrieve local app list from Splunk instance"""
    url = f"https://{hostname}.{domain}:8089/services/apps/local"
    apps_data_from_file = []

    response = requests.get(
        url,
        data={"output_mode": "json"},
        headers={"Authorization": f"Splunk {session_key}"},
        verify=securian_trust,
        timeout=30,
        params={"count": 0}
    ).json()

    splunk_default_apps = [
        "splunk_archiver", "alert_webhook", "splunk_secure_gateway", "alert_logevent",
        "apps", "appsbrowser", "introspection_generator_addon", "journald_input",
        "launcher", "learned", "search", "splunk_internal_metrics", "splunk_instrumentation",
        "legacy", "sample_app", "splunk-dashboard-studio", "splunk-rolling-upgrade",
        "splunk-visual-exporter", "splunk_gdi", "splunk_httpinput", "splunk_metrics_workspace",
        "splunk_monitoring_console", "splunk_rapid_diag", "SplunkDeploymentServerConfig",
        "SplunkForwarder", "SplunkLightForwarder"
    ]

    for entry in response.get("entry", []):
        name = entry["name"]
        if name in splunk_default_apps or "sfg" in name:
            continue
        apps_data = {
            "name": name,
            "version": entry["content"].get("version", "None")
        }
        apps_data_from_file.append(apps_data)

    return apps_data_from_file


def get_app_uuid(app_name, cookies):
    """Get app UUID from Splunkbase"""
    response = requests.get(
        f"https://splunkbase.splunk.com/apps/id/{app_name}",
        allow_redirects=False
    )
    if response.status_code != 302:
        return response.status_code
    return response.headers["Location"].split("/")[-1]


def get_latest_version(uid, cookies):
    """Get latest version info of an app from Splunkbase"""
    url = f"https://splunkbase.splunk.com/api/v1/app/{uid}/release/"
    response = requests.get(url, cookies=cookies)

    if response.status_code == 200:
        data = response.json()
        return data[0]["filename"], data[0]["name"]
    print(f"Error retrieving app version for {uid}: Status code {response.status_code}")
    return None


if __name__ == "__main__":
    try:
        # Set global config
        sfg_config = Config(region_name="us-east-1")
        sns = boto3.client("sns", config=sfg_config)
        ec2 = boto3.client("ec2", config=sfg_config)
        account_id = boto3.client("sts", config=sfg_config).get_caller_identity()["Account"]
        securian_trust = ""
        if account_id == "304008014412":
            domain = ""
        else:
            domain = ""

        SNSARN = f"arn:aws:sns:us-east-1:{account_id}:AndrewTest"
        hostname = os.uname()[1]

        # Get credentials
        admin_password = get_aws_credentials()
        username, password = get_splunkbase_credentials()
        session_key = get_session_key(admin_password, hostname, domain)

        # Get local apps and authenticate to Splunkbase
        apps_data_from_file = get_apps_list(session_key, hostname, domain)
        cookies = authenticate(username, password)

        for app in apps_data_from_file:
            app["uid"] = get_app_uuid(app["name"], cookies)

        downloaded_apps = []
        skipped_apps = []

        for app in apps_data_from_file:
            result = get_latest_version(app["uid"], cookies)
            if not result:
                continue
            app_name, latest_version = result
            if latest_version != app.get("version"):
                print(f"Upgrading {app_name} from {app.get('version')} to {latest_version}")
                downloaded_apps.append(app_name)
            else:
                print(f"Skipping {app_name}, no new version found or already up to date.")
                skipped_apps.append(app_name)

        print(f"Downloaded apps: {downloaded_apps}")
        print(f"Skipped apps: {skipped_apps}")

        message = f"Need to upgrade the following apps:\n{downloaded_apps}"
        sns.publish(TopicArn=SNSARN, Message=message, Subject="Apps Need Updated")

    except Exception as e:
        print(f"An error occurred: {str(e)}")
