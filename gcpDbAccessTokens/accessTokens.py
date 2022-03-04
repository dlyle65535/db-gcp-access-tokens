import json
import time
import argparse
import jwt
import requests


def get_jwt(account, sa_secret, timeout=3600):
    iat = time.time()
    exp = iat + timeout
    payload = {
        'iss': account,
        'sub': account,
        'aud': 'https://oauth2.googleapis.com/token',
        'iat': iat,
        'exp': exp,
        'scope': 'https://www.googleapis.com/auth/cloud-platform'
    }
    additional_headers = {'kid': sa_secret['private_key_id']}
    signed_jwt = jwt.encode(payload, sa_secret['private_key'], headers=additional_headers,
                            algorithm='RS256')
    return signed_jwt


def create_gc_access_token(jwt_token):
    url = 'https://oauth2.googleapis.com/token'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': jwt_token}
    response = requests.post(url, data=payload, headers=headers)
    token = json.loads(response.content)['access_token']
    return token


def create_oidc_token(audience, access_token, sa2):
    url = 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/' + sa2 + ':generateIdToken'
    headers = {'Authorization': 'Bearer ' + access_token, 'Content-Type': 'application/json'}
    json_data = {"delegates": [], "audience": audience, "includeEmail": "true"}
    response = requests.post(url, headers=headers, json=json_data)
    token = json.loads(response.content)['token']
    return token


def create_gc_service_token(access_token, sa2):
    url = 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/' + sa2 + ':generateAccessToken'
    headers = {'Authorization': 'Bearer ' + access_token, 'Content-Type': 'application/json'}
    json_data = {'scope': ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/compute'],
                 'lifetime': '3600s'}
    response = requests.post(url, headers=headers, json=json_data)
    return json.loads(response.content)['accessToken']


def call_api_test(account_id, sa2_oidc_token, sa2_access_token):
    # for some reason, the leading space is required to make this work
    url = ' https://accounts.gcp.databricks.com/api/2.0/accounts/' + account_id + '/workspaces'
    headers = {'Authorization': 'Bearer ' + sa2_oidc_token, 'X-Databricks-GCP-SA-Access-Token': sa2_access_token}
    response = requests.get(url, headers=headers)
    return response.content


def call_file_test(account_id, sa2_oidc_token, sa2_access_token):
    url = ' https://accounts.gcp.databricks.com/api/2.0/accounts/' + account_id + '/usage/download'
    payload = {'start_month': '2022-01', 'end_month': '2022-03'}
    headers = {'Authorization': 'Bearer ' + sa2_oidc_token, 'X-Databricks-GCP-SA-Access-Token': sa2_access_token}
    response = requests.get(url, headers=headers, params=payload)
    return response.content


def create_pat(workspace_url, access_token, comment, lifetime=3600):
    url = workspace_url + '/api/2.0/token/create'
    headers = {'Authorization': 'Bearer ' + access_token, 'Content-Type': 'application/json'}
    json_data = {'comment': comment, 'lifetime_seconds': lifetime}
    response = requests.post(url, headers=headers, json=json_data)
    return response.content


def delete_pat(workspace_url, access_token, pat_id):
    url = workspace_url + '/api/2.0/token/delete'
    headers = {'Authorization': 'Bearer ' + access_token, 'Content-Type': 'application/json'}
    json_data = {'token_id': pat_id}
    response = requests.post(url, headers=headers, json=json_data)
    return response.content


def list_pat(workspace_url, access_token):
    url = workspace_url + '/api/2.0/token/list'
    headers = {'Authorization': 'Bearer ' + access_token, 'Content-Type': 'application/json'}
    response = requests.get(url, headers=headers)
    return response.content


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sa1', type=str, required=True)
    parser.add_argument('--sa2', type=str, required=True)
    parser.add_argument('--workspaceurl', type=str, required=True)
    parser.add_argument('--keypath', type=str, required=True)
    parser.add_argument('--timeout', type=str, default=3600)
    args = parser.parse_args()

    sa_secret = json.load(open(args.keypath))

    signed_jwt = get_jwt(args.sa1, sa_secret, args.timeout)
    access_token_sa1 = create_gc_access_token(signed_jwt)
    sa2_workspace_token = create_oidc_token(args.workspaceurl, access_token_sa1, args.sa2)

    print(create_pat(args.workspaceurl, sa2_workspace_token, "Example Token"))
    print("SA2 OIDC Token (accounts): " + create_oidc_token('https://accounts.gcp.databricks.com', access_token_sa1,
                                                            args.sa2))
    print("SA2 OIDC Token (workspace): " + sa2_workspace_token)
    print("SA2 ACCESS Token: " + create_gc_service_token(access_token_sa1, args.sa2))


if __name__ == "__main__":
    main()
