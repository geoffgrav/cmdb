import requests
import json
import logging
import os
import datetime
import csv
import time
import base64
from dotenv import load_dotenv
from urllib.parse import urlparse
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def get_v1_base_url(customer_csv):
    """Get V1 API base URL"""
    return f"{customer_csv['gravitee_url']}/management/organizations/{customer_csv['org_id']}/environments/{customer_csv['env_id']}"

def get_v2_base_url(customer_csv):
    """Get V2 API base URL"""
    return f"{customer_csv['gravitee_url']}/management/v2/environments/{customer_csv['env_id']}"

def get_customer_id(url):
    """Extract customer ID from URL (e.g., 'cardiff' from 'demo.apim.cardiff.az.gravitee.io')"""
    try:
        parsed_url = urlparse(url)
        parts = parsed_url.netloc.split('.')
        if 'gravitee' in parts:
            gravitee_index = parts.index('gravitee')
            if gravitee_index >= 3:
                return parts[gravitee_index - 3].lower()
            else:
                logging.warning("Not enough parts in domain to extract customer ID")
    except Exception as e:
        logging.error(f"Error parsing URL for customer ID: {e}")
    return "default"

def create_session():
    """Create a requests session with retry logic"""
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

def read_customer_csv(csv_path):
    """Read customer information from CSV file"""
    if not csv_path:
        raise ValueError("CUSTOMER_CSV_PATH environment variable is required")
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Customer CSV file not found: {csv_path}")

    customers = []
    try:
        with open(csv_path, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                required_fields = ['gravitee_url', 'customer_name']
                missing_fields = [field for field in required_fields if field not in row]
                if missing_fields:
                    raise ValueError(f"Missing required fields in CSV: {', '.join(missing_fields)}")

                customers.append({
                    'gravitee_url': row['gravitee_url'].strip().rstrip('/'),
                    'org_id': row['org_id'].strip(),
                    'env_id': row['env_id'].strip(),
                    'customer_name': row['customer_name'].strip(),
                    'auth_method': row['auth_method'].strip(),
                    'auth1': row.get('auth1', '').strip(),
                    'auth2': row.get('auth2', '').strip()
                })
        logging.info(f"Successfully loaded {len(customers)} customers from CSV")
        return customers
    except Exception as e:
        logging.error(f"Error reading customer CSV: {e}")
        raise


def get_auth_header(auth_method, auth1, auth2):
    if auth_method == "Basic":
        token = base64.b64encode(f"{auth1}:{auth2}".encode()).decode()
    else:
        token = auth1
    return {"Authorization": f"{auth_method} {token}"}

def fetch_apis(customer_csv, headers, session):
    """Fetch APIs using v2 endpoint with pagination"""
    all_apis = []
    base_url = get_v2_base_url(customer_csv)

    page = 1
    per_page = 100

    while True:
        try:
            url = f"{base_url}/apis?page={page}&size={per_page}"
            logging.info(f"Fetching APIs page {page} from: {url}")

            response = session.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()

            if not isinstance(data, dict):
                logging.error(f"Unexpected response format: {type(data)}")
                break

            apis = data.get("data", [])
            if not apis:
                break

            all_apis.extend(apis)

            pagination = data.get("pagination", {})
            current_page = pagination.get("page", 1)
            total_pages = pagination.get("pageCount", 1)

            if current_page >= total_pages:
                break

            page += 1

        except Exception as e:
            logging.error(f"Error fetching APIs page {page}: {e}")
            break

    return all_apis

def fetch_api_plans(api_id, customer_csv, headers, session):
    """Fetch API plans using V2 endpoint with pagination"""
    try:
        url = f"{get_v2_base_url(customer_csv)}/apis/{api_id}/plans?page=1&perPage=9999&statuses=STAGING,PUBLISHED,DEPRECATED,CLOSED"
        logging.info(f"Fetching API plans from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Extract plans data from response
        plans = data.get("data", [])
        logging.info(f"Found {len(plans)} plans for API {api_id}")
        return plans
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch plans for API {api_id}: {e}")
        return []

def fetch_api_pages(api_id, customer_csv, headers, session):
    """Fetch API documentation pages using V2 endpoint with enhanced processing"""
    try:
        url = f"{get_v2_base_url(customer_csv)}/apis/{api_id}/pages"
        logging.info(f"Fetching API pages from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        pages = response.json()

        # Handle both array and object responses
        if isinstance(pages, dict) and 'pages' in pages:
            pages = pages['pages']
        elif isinstance(pages, dict) and 'data' in pages:
            pages = pages['data']
        elif not isinstance(pages, list):
            pages = [pages] if pages else []

        # Create enhanced documentation structure
        documentation = {
            "pages_per_type": {},
            "pages": [],
            "stats": {
                "total_count": len(pages),
                "by_type": {},
                "by_visibility": {},
                "by_status": {}
            }
        }

        # Process each page
        for page in pages:
            page_type = page.get("type", "unknown")
            visibility = page.get("visibility", "unknown")
            published = page.get("published", False)

            # Update pages_per_type count
            documentation["pages_per_type"][page_type] = documentation["pages_per_type"].get(page_type, 0) + 1

            # Update stats
            documentation["stats"]["by_type"][page_type] = documentation["stats"]["by_type"].get(page_type, 0) + 1
            documentation["stats"]["by_visibility"][visibility] = documentation["stats"]["by_visibility"].get(visibility, 0) + 1
            status = "published" if published else "unpublished"
            documentation["stats"]["by_status"][status] = documentation["stats"]["by_status"].get(status, 0) + 1

            # Add detailed page info
            page_info = {
                "name": page.get("name", "unknown"),
                "type": page_type,
                "content_present": bool(page.get("content")),
                "published": published,
                "visibility": visibility
            }
            documentation["pages"].append(page_info)

        return documentation
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch pages for API {api_id}: {e}")
        return {
            "pages_per_type": {},
            "pages": [],
            "stats": {
                "total_count": 0,
                "by_type": {},
                "by_visibility": {},
                "by_status": {}
            }
        }

def fetch_api_details(api_id, customer_csv, headers, session):
    """Fetch detailed API information"""
    try:
        url = f"{get_v2_base_url(customer_csv)}/apis/{api_id}"
        logging.info(f"Fetching API details from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch API details for {api_id}: {e}")
        return {}

def fetch_api_subscriptions(api_id, customer_csv, headers, session):
    """Fetch API subscriptions"""
    try:
        url = f"{get_v2_base_url(customer_csv)}/apis/{api_id}/subscriptions?status=ACCEPTED,CLOSED,PAUSED,PENDING,REJECTED,RESUMED"
        logging.info(f"Fetching API subscriptions from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data.get("data", [])
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch subscriptions for API {api_id}: {e}")
        return []

def fetch_api_alerts(api_id, customer_csv, headers, session):
    """Fetch API alerts using V1 endpoint"""
    try:
        url = f"{get_v1_base_url(customer_csv)}/apis/{api_id}/alerts"
        logging.info(f"Fetching API alerts from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch alerts for API {api_id}: {e}")
        return []

def fetch_applications(customer_csv, headers, session):
    """Fetch applications using V1 endpoint"""
    try:
        url = f"{get_v1_base_url(customer_csv)}/applications"
        logging.info(f"Fetching applications from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch applications: {e}")
        return []

def fetch_app_subscriptions(app_id, customer_csv, headers, session):
    """Fetch application subscriptions using V1 endpoint"""
    try:
        url = f"{get_v1_base_url(customer_csv)}/applications/{app_id}/subscribed"
        logging.info(f"Fetching app subscriptions from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch subscriptions for app {app_id}: {e}")
        return []

def fetch_app_alerts(app_id, customer_csv, headers, session):
    """Fetch application alerts using V1 endpoint"""
    try:
        url = f"{get_v1_base_url(customer_csv)}/applications/{app_id}/alerts"
        logging.info(f"Fetching app alerts from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch alerts for app {app_id}: {e}")
        return []

def fetch_users(customer_csv, headers, session):
    """Fetch users using V1 endpoint with pagination"""
    all_users = []
    page = 1
    per_page = 20

    while True:
        try:
            url = f"{get_v1_base_url(customer_csv)}/users?page={page}&size={per_page}"
            logging.info(f"Fetching users page {page} from: {url}")
            response = session.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()

            if not isinstance(data, dict):
                logging.error(f"Unexpected response format: {type(data)}")
                break

            users = data.get("data", [])
            if not users:
                break

            all_users.extend(users)

            # Check pagination
            pagination = data.get("page", {})
            current_page = pagination.get("current", 1)
            total_pages = pagination.get("total_pages", 1)

            if current_page >= total_pages:
                break

            page += 1
            time.sleep(0.5)  # Add small delay between pages

        except Exception as e:
            logging.error(f"Error fetching users page {page}: {e}")
            break

    return all_users

def fetch_gko_apis(customer_csv, headers, session):
    """Fetch GKO-managed APIs using V1 endpoint"""
    try:
        url = f"{get_v1_base_url(customer_csv)}/apis"
        logging.info(f"Fetching GKO APIs from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        apis = response.json()

        # Check for GKO APIs by looking at definition_context.originKubernetes
        gko_apis = [
            api for api in apis
            if api.get('definition_context', {}).get('originKubernetes', False) or
               api.get('originContext', {}).get('origin') == 'KUBERNETES'
        ]

        logging.info(f"Found {len(gko_apis)} GKO-managed APIs")
        return gko_apis
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch GKO APIs: {e}")
        return []

def fetch_dictionaries(customer_csv, headers, session):
    """Fetch dictionaries using V1 endpoint"""
    try:
        url = f"{get_v1_base_url(customer_csv)}/configuration/dictionaries"
        logging.info(f"Fetching dictionaries from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch dictionaries: {e}")
        return []

def map_policy_name(policy_name):
    """Map a Gravitee policy name to its standardized form"""
    POLICY_MAP = {
        "API Key": "API ~Key",
        "Assign Attributes": "Assign Attributes",
        "Assign Content": "Assign Content",
        "Assign Metrics": "Assign Metrics",
        "AVRO to JSON": "AVRO to JSON",
        "AVRO to Protobuf": "AVRO to Protobuf",
        "AWS Lambda": "AWS Lambda",
        "Basic Auth": "Basic Authentication",
        "Cache": "Cache",
        "Circuit Breaker": "Circuit Breaker",
        "Cloud Events": "Cloud Events",
        "Data Cache": "Data Cache",
        "Dynamic Routing": "Dynamic Routing",
        "Generate JWT": "Generate JWT",
        "GeoIP Filtering": "GeoIP Filtering",
        "Groovy": "Groovy",
        "HTTP Callout": "HTTP Callout",
        "Javascript": "Javascript",
        "JSON to JSON": "JSON to JSON",
        "JSON to XML": "JSON to XML",
        "Rate Limit": "Rate Limiting",
        "Transform Headers": "Transform Headers",
        "Mock": "Mock",
        "OAuth2": "OAuth2",
        "Assign attributes": "Assign Attributes",
        "Transform Headers": "Transform Headers",
        "Assign metrics": "Assign Metrics"
    }
    return POLICY_MAP.get(policy_name, policy_name)
def redact_sensitive_config(config):
    if not isinstance(config, dict):
        return config

    redacted = {}
    for key, value in config.items():
        key_lower = key.lower()
        if key_lower in {"authorization", "value", "token", "secret", "password"}:
            redacted[key] = "[REDACTED]"
        elif isinstance(value, list):
            redacted[key] = [
                {
                    k: "[REDACTED]" if k.lower() in {"authorization", "value", "token", "secret", "password"} else v
                    for k, v in item.items()
                } if isinstance(item, dict) else item
                for item in value
            ]
        else:
            redacted[key] = value
    return redacted

def extract_policies_from_flows(flows, plan_name="", plan_security=""):
    """Extract and map policy names from API flows"""
    policies_info = []
    unique_policies = set()

    for flow in flows:
        flow_policies = {
            "pre_policies": [],
            "post_policies": [],
            "flow_name": flow.get("name", ""),
            "flow_path": flow.get("path", ""),
            "flow_condition": flow.get("condition", ""),
            "flow_methods": flow.get("methods", [])
        }

        # Process pre-request policies
        for policy in flow.get("pre", []):
            policy_name = policy.get("name", "unknown")
            mapped_name = map_policy_name(policy_name)
            unique_policies.add(mapped_name)

            policy_info = {
                "name": policy_name,
                "mapped_name": mapped_name,
                "type": "pre",
                "enabled": policy.get("enabled", False),
                "plan_name": plan_name,
                "plan_security": plan_security,
                "configuration": redact_sensitive_config(policy.get("configuration", {})),
                "description": policy.get("description", "")
            }
            flow_policies["pre_policies"].append(policy_info)

        # Process post-request policies
        for policy in flow.get("post", []):
            policy_name = policy.get("name", "unknown")
            mapped_name = map_policy_name(policy_name)
            unique_policies.add(mapped_name)

            policy_info = {
                "name": policy_name,
                "mapped_name": mapped_name,
                "type": "post",
                "enabled": policy.get("enabled", False),
                "plan_name": plan_name,
                "plan_security": plan_security,
                "configuration": redact_sensitive_config(policy.get("configuration", {})),
                "description": policy.get("description", "")
            }
            flow_policies["post_policies"].append(policy_info)

        flow_policies["unique_policies"] = list(unique_policies)
        policies_info.append(flow_policies)

    return policies_info

def fetch_api_analytics(api_id, customer_csv, headers, session, days=30):
    """Fetch API analytics (hit counts) for a given time period"""
    try:
        current_time = int(time.time() * 1000)
        from_time = current_time - (days * 24 * 60 * 60 * 1000)

        url = f"{get_v1_base_url(customer_csv)}/apis/{api_id}/analytics"
        params = {
            'type': 'COUNT',
            'from': from_time,
            'to': current_time,
            'interval': 86400000  # 1 day
        }

        logging.info(f"Fetching analytics for API {api_id} from {from_time} to {current_time}")
        response = session.get(url, headers=headers, params=params)
        response.raise_for_status()

        data = response.json()
        return {
            "total_hits": data.get("hits", 0),
            "time_period": f"last_{days}_days",
            "from_timestamp": from_time,
            "to_timestamp": current_time,
            "raw_data": data
        }
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch analytics for API {api_id}: {e}")
        return {
            "total_hits": 0,
            "time_period": f"last_{days}_days",
            "error": str(e)
        }

def process_api_details(api_id, api_name, api_details, collected_data, customer_csv, headers, session):
    """Process details for a single API with enhanced documentation handling"""
    try:
        # Initialize API data structure
        api_data = {
            "name": api_name,
            "version": api_details.get("apiVersion", "unknown"),
            "type": api_details.get("type", "unknown"),
            "plans": {
                "count_per_type": {},
                "total": 0,
                "items": []  # Store actual plan items
            },
            "subscriptions": {
                "count": 0
            },
            "alerts": {
                "count": 0
            },
            "documentation": {
                "pages_per_type": {},
                "pages": [],
                "stats": {
                    "total_count": 0,
                    "by_type": {},
                    "by_visibility": {},
                    "by_status": {}
                },
                "fetchers": []
            },
            "dictionaries": {
                "count": 0,
                "types": {}
            },
            "design": {
                "flow_count": 0,
                "policies_per_flow": [],
                "flow_mode": api_details.get("flow_mode", ""),
                "resources": api_details.get("resources", []),
                "response_templates_count": len(api_details.get("response_templates", {})),
                "properties_count": len(api_details.get("properties", []))
            },
            "endpoint_groups": {
                "count": 0,
                "details": []
            },
            "entrypoints": {
                "count": 0,
                "details": []
            }
        }

        # Process dictionaries
        try:
            dictionaries = fetch_dictionaries(customer_csv, headers, session)
            dictionary_types = {}
            for dictionary in dictionaries:
                dict_type = dictionary.get("type", "unknown")
                dictionary_types[dict_type] = dictionary_types.get(dict_type, 0) + 1

            api_data["dictionaries"] = {
                "count": len(dictionaries),
                "types": dictionary_types
            }
            collected_data["dictionaries"]["total_count"] = len(dictionaries)
            logging.info(f"Processed {len(dictionaries)} dictionaries for API {api_id}")
        except Exception as e:
            logging.error(f"Error processing dictionaries for API {api_id}: {e}")
            api_data["dictionaries"] = {"count": 0, "types": {}}

        # Process documentation pages with enhanced information
        try:
            documentation = fetch_api_pages(api_id, customer_csv, headers, session)
            api_data["documentation"] = documentation

            # Extract fetchers from pages
            fetchers = set()
            for page in documentation["pages"]:
                if isinstance(page, dict):
                    # Handle source configuration
                    source = page.get("source", {})
                    if isinstance(source, dict):
                        source_type = source.get("type")
                        if source_type:
                            fetchers.add(source_type)

                    # Handle configuration viewer
                    config = page.get("configuration", {})
                    if isinstance(config, dict):
                        viewer = config.get("viewer")
                        if viewer:
                            fetchers.add(viewer)

            api_data["documentation"]["fetchers"] = list(fetchers)

        except Exception as e:
            logging.error(f"Error processing API pages for {api_id}: {e}")
            api_data["documentation"] = {
                "pages_per_type": {},
                "pages": [],
                "stats": {
                    "total_count": 0,
                    "by_type": {},
                    "by_visibility": {},
                    "by_status": {}
                },
                "fetchers": []
            }

        # Fetch and process plans
        plans = fetch_api_plans(api_id, customer_csv, headers, session)
        plan_type_counts = {}

        for plan in plans:
            # Extract the security type correctly from the plan data
            if isinstance(plan.get("security"), dict):
                plan_type = plan.get("security", {}).get("type", "unknown").lower()
            else:
                plan_type = plan.get("security", "unknown").lower()

            plan_type_counts[plan_type] = plan_type_counts.get(plan_type, 0) + 1

            # Add the plan to the items list
            plan_data = {
                "id": plan.get("id", "unknown"),
                "name": plan.get("name", "unknown"),
                "description": plan.get("description", ""),
                "security_type": plan_type,
                "status": plan.get("status", "unknown"),
                "order": plan.get("order", 0),
                "mode": plan.get("mode", "unknown"),
                "created_at": plan.get("createdAt", ""),
                "updated_at": plan.get("updatedAt", ""),
                "published_at": plan.get("publishedAt", ""),
                "validation": plan.get("validation", "unknown"),
                "comment_required": plan.get("commentRequired", False),
                "type": plan.get("type", "unknown")
            }

            # Add minimal security config info for analytics only
            if isinstance(plan.get("security"), dict):
                plan_data["security_signature"] = plan["security"].get("configuration", {}).get("signature", "")
                # Don't log resolverParameter or other secrets

            # Process flows if available
            plan_flows = plan.get("flows", [])
            if plan_flows:
                plan_data["flows"] = []
                for flow in plan_flows:
                    flow_data = {
                        "id": flow.get("id", "unknown"),
                        "name": flow.get("name", ""),
                        "enabled": flow.get("enabled", False),
                        "path": "",
                        "methods": []
                    }

                    # Extract selectors
                    selectors = flow.get("selectors", [])
                    for selector in selectors:
                        if selector.get("type") == "HTTP":
                            flow_data["path"] = selector.get("path", "")
                            flow_data["path_operator"] = selector.get("pathOperator", "")
                            flow_data["methods"] = selector.get("methods", [])

                    # Process request policies
                    request_policies = []
                    for policy in flow.get("request", []):
                        policy_data = {
                            "name": policy.get("name", "unknown"),
                            "description": policy.get("description", ""),
                            "enabled": policy.get("enabled", False),
                            "policy": policy.get("policy", "unknown"),
                            "configuration": policy.get("configuration", {})
                        }
                        request_policies.append(policy_data)

                    flow_data["request_policies"] = request_policies

                    # Process response policies
                    response_policies = []
                    for policy in flow.get("response", []):
                        policy_data = {
                            "name": policy.get("name", "unknown"),
                            "description": policy.get("description", ""),
                            "enabled": policy.get("enabled", False),
                            "policy": policy.get("policy", "unknown"),
                            "configuration": policy.get("configuration", {})
                        }
                        response_policies.append(policy_data)

                    flow_data["response_policies"] = response_policies

                    # Add the flow to the plan's flows
                    plan_data["flows"].append(flow_data)

            # Add the plan to the list of items
            api_data["plans"]["items"].append(plan_data)

            # Process plan flows for policy extraction (for backward compatibility)
            if plan_flows:
                plan_policies = extract_policies_from_flows(
                    plan_flows,
                    plan_name=plan.get("name", "unknown"),
                    plan_security=plan_type
                )
                api_data["design"]["policies_per_flow"].extend(plan_policies)

        # Update the plan counts
        api_data["plans"]["count_per_type"] = plan_type_counts
        api_data["plans"]["total"] = len(plans)

        # Process subscriptions
        subscriptions = fetch_api_subscriptions(api_id, customer_csv, headers, session)
        api_data["subscriptions"]["count"] = len(subscriptions)

        # Process alerts
        alerts = fetch_api_alerts(api_id, customer_csv, headers, session)
        api_data["alerts"]["count"] = len(alerts)

        # Process flows
        flows = api_details.get("flows", [])
        api_policies = extract_policies_from_flows(flows)
        api_data["design"]["flow_count"] = len(flows)
        api_data["design"]["policies_per_flow"].extend(api_policies)

        # Process endpoint groups
        proxy = api_details.get("proxy", {})
        groups = proxy.get("groups", [])
        api_data["endpoint_groups"]["count"] = len(groups)

        for group in groups:
            group_info = {
                "name": group.get("name", "unknown"),
                "endpoints": [{
                    "type": endpoint.get("type", "unknown"),
                    "url": endpoint.get("target", "unknown"),
                    "name": endpoint.get("name", "unknown"),
                    "backup": endpoint.get("backup", False),
                    "inherit": endpoint.get("inherit", True)
                } for endpoint in group.get("endpoints", [])]
            }
            api_data["endpoint_groups"]["details"].append(group_info)

        # Process entrypoints
        listeners = api_details.get("listeners", [])
        all_entrypoints = []

        # Extract entrypoints from each listener
        for listener in listeners:
            listener_entrypoints = listener.get("entrypoints", [])
            for entrypoint in listener_entrypoints:
                entrypoint_data = {
                    "type": entrypoint.get("type", "default"),
                    "qos": entrypoint.get("qos", "unknown"),  # Include qos field
                    "configuration": entrypoint.get("configuration", {}),  # Include configuration
                    # You can keep these fields as defaults if they might exist in other API versions
                    "target": entrypoint.get("target", "unknown"),
                    "tags": entrypoint.get("tags", []),
                    "inherit": entrypoint.get("inherit", True)
                }
                all_entrypoints.append(entrypoint_data)
        
        # Fetch API analytics
        try:
            analytics = fetch_api_analytics(api_id, customer_csv, headers, session)
            api_data["analytics"] = analytics
            logging.info(f"API {api_id} had {analytics['total_hits']} hits in last 30 days")
        except Exception as e:
            logging.error(f"Error fetching analytics for API {api_id}: {e}")
            api_data["analytics"] = {
                "total_hits": 0,
                "error": str(e)
            }

        # Store the collected entrypoints
        api_data["entrypoints"] = all_entrypoints

        collected_data["apis"]["details"][api_id] = api_data
        return collected_data

    except Exception as e:
        logging.error(f"Error processing API details for {api_id}: {e}")
        return collected_data

def main():
    try:
        # Read customer information from CSV
        csv_path = os.getenv("CUSTOMER_CSV_PATH")
        if not csv_path:
            raise ValueError("CUSTOMER_CSV_PATH environment variable is required")

        customers = read_customer_csv(csv_path)
        if not customers:
            raise ValueError("No customers found in CSV file")

        # Create output directory
        output_dir = "gravitee_data"
        os.makedirs(output_dir, exist_ok=True)

        # Create session for requests
        session = create_session()

        # Process each customer
        for customer in customers:
            try:
                logging.info(f"Processing customer: {customer['customer_name']}")
                if customer['auth_method'] not in ('Bearer', 'Basic'):
                    logging.error(f"Unknown authentication method. It must be 'Bearer' or 'Basic'")
                    continue

                if customer['auth_method'] == 'Basic' and (not customer['auth1'] or not customer['auth2']):
                    logging.error(f"Missing username or password for customer {customer['customer_name']}")
                    continue

                headers = get_auth_header(customer['auth_method'], customer['auth1'], customer['auth2'])

                # Initialize data collection
                # Initialize data collection structure
                collected_data = {
                    "customer_info": {
                        "customer_id": get_customer_id(customer['gravitee_url']),
                        "customer_name": customer['customer_name'],
                        "gravitee_url": customer['gravitee_url'],
                        "org_id": customer['org_id'],
                        "env_id": customer['env_id'],
                        "extraction_date": datetime.datetime.now().isoformat()
                    },
                    "apis": {
                        "total_count": 0,
                        "details": {}
                    },
                    "dictionaries": {
                        "total_count": 0
                    },
                    "applications": {
                        "total_count": 0,
                        "details": {}
                    },
                    "users": {
                        "total_count": 0,
                        "details": []
                    },
                    "gko": {
                        "apis_count": 0,
                        "details": []
                    }
                }

                # Fetch and process GKO APIs
                try:
                    gko_apis = fetch_gko_apis(customer, headers, session)
                    collected_data["gko"]["apis_count"] = len(gko_apis)

                    # Add additional GKO details
                    collected_data["gko"]["details"] = [{
                        "id": api.get("id", "unknown"),
                        "name": api.get("name", "unknown"),
                        "version": api.get("version", "unknown"),
                        "description": api.get("description", ""),
                        "state": api.get("state", "unknown"),
                        "context_path": api.get("context_path", ""),
                        "definition_context": {
                            "origin": api.get("definition_context", {}).get("origin", "unknown"),
                            "mode": api.get("definition_context", {}).get("mode", "unknown"),
                            "syncFrom": api.get("definition_context", {}).get("syncFrom", "unknown"),
                            "originKubernetes": api.get("definition_context", {}).get("originKubernetes", False)
                        },
                        "originContext": {
                            "origin": api.get("originContext", {}).get("origin", "unknown"),
                            "mode": api.get("originContext", {}).get("mode", "unknown"),
                            "syncFrom": api.get("originContext", {}).get("syncFrom", "unknown")
                        },
                        "created_at": api.get("created_at", "unknown"),
                        "updated_at": api.get("updated_at", "unknown"),
                        "deployed_at": api.get("deployed_at", "unknown")
                    } for api in gko_apis]

                    logging.info(f"Found {len(gko_apis)} GKO-managed APIs for {customer['customer_name']}")
                except Exception as e:
                    logging.error(f"Error processing GKO APIs for {customer['customer_name']}: {e}")

                # Fetch and process Users
                try:
                    users = fetch_users(customer, headers, session)
                    collected_data["users"]["total_count"] = len(users)
                    logging.info(f"Found {len(users)} users for {customer['customer_name']}")

                    collected_data["users"]["details"] = []
                    for user in users:
                        user_data = {
                            "id": user.get("id", "unknown"),
                            "firstname": user.get("firstname", ""),
                            "lastname": user.get("lastname", ""),
                            "email": user.get("email", ""),
                            "organizationId": user.get("organizationId", "unknown"),
                            "source": user.get("source", "unknown"),
                            "sourceId": user.get("sourceId", "unknown"),
                            "status": user.get("status", "unknown"),
                            "displayName": user.get("displayName", "unknown"),
                            "primary_owner": user.get("primary_owner", False),
                            "created_at": user.get("created_at", "unknown"),
                            "updated_at": user.get("updated_at", "unknown"),
                            "lastConnectionAt": user.get("lastConnectionAt"),
                            "firstConnectionAt": user.get("firstConnectionAt"),
                            "loginCount": user.get("loginCount", 0),
                            "number_of_active_tokens": user.get("number_of_active_tokens", 0),
                            "customFields": user.get("customFields", {}),
                            "picture": user.get("picture"),
                        }

                        # Add statistics to the user data
                        connection_stats = {
                            "days_since_last_login": None,
                            "days_since_creation": None,
                            "login_frequency": None  # average logins per month since creation
                        }

                        try:
                            now = datetime.datetime.now()

                            # Calculate days since last login
                            if user.get("lastConnectionAt"):
                                last_login = datetime.datetime.fromtimestamp(user["lastConnectionAt"] / 1000)
                                connection_stats["days_since_last_login"] = (now - last_login).days

                            # Calculate days since account creation
                            if user.get("created_at"):
                                created_date = datetime.datetime.fromtimestamp(user["created_at"] / 1000)
                                days_since_creation = (now - created_date).days
                                connection_stats["days_since_creation"] = days_since_creation

                                # Calculate login frequency (logins per month)
                                if days_since_creation > 0:
                                    months_since_creation = days_since_creation / 30.0  # approximate
                                    login_count = user.get("loginCount", 0)
                                    connection_stats["login_frequency"] = round(login_count / months_since_creation, 2)
                        except Exception as e:
                            logging.error(f"Error calculating user statistics: {e}")

                        user_data["connection_stats"] = connection_stats
                        collected_data["users"]["details"].append(user_data)

                    logging.info(f"Successfully processed user details for {customer['customer_name']}")
                except Exception as e:
                    logging.error(f"Error processing users for {customer['customer_name']}: {e}")

                # Fetch and process Applications
                try:
                    applications = fetch_applications(customer, headers, session)
                    collected_data["applications"]["total_count"] = len(applications)
                    logging.info(f"Found {len(applications)} applications for {customer['customer_name']}")

                    for app in applications:
                        app_id = app.get("id")
                        if not app_id:
                            continue

                        app_data = {
                            "name": app.get("name", "Unknown Application"),
                            "description": app.get("description", ""),
                            "type": app.get("type", "unknown"),
                            "domain": app.get("domain", ""),
                            "status": app.get("status", "unknown"),
                            "created_at": app.get("created_at", "unknown"),
                            "updated_at": app.get("updated_at", "unknown"),
                            "groups": app.get("groups", []),
                            "origin": app.get("origin", "unknown"),
                            "settings": {
                                "oauth": app.get("settings", {}).get("oauth", {}),
                                "app": app.get("settings", {}).get("app", {})
                            },
                            "api_key_mode": app.get("api_key_mode", "unknown"),
                            "disable_membership_notifications": app.get("disable_membership_notifications", False),
                            "owner": {
                                "id": app.get("owner", {}).get("id", "unknown"),
                                "email": app.get("owner", {}).get("email", ""),
                                "displayName": app.get("owner", {}).get("displayName", "unknown"),
                                "type": app.get("owner", {}).get("type", "unknown")
                            },
                            "picture_url": app.get("picture_url", ""),
                            "subscriptions": {
                                "count": 0,
                                "details": []
                            },
                            "alerts": {
                                "count": 0
                            }
                        }

                        # Fetch and process app subscriptions
                        try:
                            subscriptions = fetch_app_subscriptions(app_id, customer, headers, session)
                            app_data["subscriptions"]["count"] = len(subscriptions)
                            app_data["subscriptions"]["details"] = [{
                                "api": sub.get("api", {}).get("name", "unknown"),
                                "plan": sub.get("plan", {}).get("name", "unknown"),
                                "status": sub.get("status", "unknown")
                            } for sub in subscriptions]
                        except Exception as e:
                            logging.error(f"Error processing subscriptions for app {app_id}: {e}")

                        # Fetch and process app alerts
                        try:
                            alerts = fetch_app_alerts(app_id, customer, headers, session)
                            app_data["alerts"]["count"] = len(alerts)
                        except Exception as e:
                            logging.error(f"Error processing alerts for app {app_id}: {e}")

                        collected_data["applications"]["details"][app_id] = app_data
                        logging.info(f"Processed application: {app_data['name']} (ID: {app_id})")

                except Exception as e:
                    logging.error(f"Error processing applications for {customer['customer_name']}: {e}")

                # Fetch and process APIs
                apis = fetch_apis(customer, headers, session)
                if not apis:
                    logging.error(f"No APIs found for customer {customer['customer_name']}")
                    continue

                collected_data["apis"]["total_count"] = len(apis)
                logging.info(f"Found {len(apis)} APIs for {customer['customer_name']}")

                # Process each API
                for api in apis:
                    api_id = api.get("id")
                    api_name = api.get("name", "Unknown API")
                    api_version = api.get("version", "unknown")

                    logging.info(f"Processing API: {api_name} (ID: {api_id}, Version: {api_version})")

                    try:
                        # Fetch detailed API information
                        api_details = fetch_api_details(api_id, customer, headers, session)
                        if not api_details:
                            logging.error(f"Could not fetch details for API {api_id}")
                            continue

                        # Process API details
                        collected_data = process_api_details(
                            api_id,
                            api_name,
                            api_details,
                            collected_data,
                            customer,
                            headers,
                            session
                        )

                        logging.info(f"Successfully processed API: {api_name} (ID: {api_id})")

                    except Exception as e:
                        logging.error(f"Error processing API {api_id}: {str(e)}")
                        continue

                # Save collected data
                if collected_data["apis"]["details"]:
                    try:
                        customer_id = get_customer_id(customer['gravitee_url'])
                        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

                                                # Determine output file name
                        customer_id = get_customer_id(customer['gravitee_url'])
                        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                        filename = f"{output_dir}/gravitee_data_{customer_id}_{timestamp}.json"

                        # Keep only the fields that map to BigQuery tables
                        keys_to_keep = ["apis", "applications", "users", "gko", "dictionaries", "customer_info"]
                        filtered_data = {key: collected_data[key] for key in keys_to_keep if key in collected_data}

                        # Save filtered data file
                        with open(filename, 'w', encoding='utf-8') as f:
                            json.dump(filtered_data, f, indent=2, ensure_ascii=False)
                        logging.info(f"Successfully saved data for {customer['customer_name']} to {filename}")

                        # Save summary file
                        summary = {
                            "customer_name": customer['customer_name'],
                            "extraction_date": timestamp,
                            "total_apis": collected_data["apis"]["total_count"],
                            "apis_processed": len(collected_data["apis"]["details"]),
                            "gko_apis": collected_data["gko"]["apis_count"],
                            "applications": {
                                "total": collected_data["applications"]["total_count"],
                                "by_type": {},
                                "by_status": {},
                                "by_owner": {}
                            },
                            "file_location": filename
                        }

                        # Calculate application statistics
                        app_stats = {
                            "by_type": {},
                            "by_status": {},
                            "by_owner": {}
                        }

                        for app in collected_data["applications"]["details"].values():
                            # Count by type
                            app_type = app.get("type", "unknown")
                            app_stats["by_type"][app_type] = app_stats["by_type"].get(app_type, 0) + 1

                            # Count by status
                            app_status = app.get("status", "unknown")
                            app_stats["by_status"][app_status] = app_stats["by_status"].get(app_status, 0) + 1

                            # Count by owner
                            owner_name = app.get("owner", {}).get("displayName", "unknown")
                            app_stats["by_owner"][owner_name] = app_stats["by_owner"].get(owner_name, 0) + 1

                        summary["applications"].update(app_stats)
                        summary_filename = f"{output_dir}/summary_{customer_id}_{timestamp}.json"
                        with open(summary_filename, 'w', encoding='utf-8') as f:
                            json.dump(summary, f, indent=2)
                        logging.info(f"Saved summary to {summary_filename}")

                    except Exception as e:
                        logging.error(f"Error saving data for {customer['customer_name']}: {e}")
                else:
                    logging.error(f"No API data collected for {customer['customer_name']}")

            except Exception as e:
                logging.error(f"Error processing customer {customer['customer_name']}: {e}")
                continue

        logging.info("Completed processing all customers")

    except Exception as e:
        logging.error(f"Fatal error in main execution: {e}")
        raise

if __name__ == "__main__":
    main()
