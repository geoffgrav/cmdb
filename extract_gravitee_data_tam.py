import requests
import json
import logging
import os
import datetime
import csv
import time
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

def get_v1_base_url(url):
    """Get V1 API base URL"""
    return f"{url}/management/organizations/DEFAULT/environments/DEFAULT"

def get_v2_base_url(url):
    """Get V2 API base URL"""
    return f"{url}/management/v2/environments/DEFAULT"

def get_customer_id(url):
    """Extract customer ID from URL"""
    try:
        parsed_url = urlparse(url)
        parts = parsed_url.netloc.split('.')
        for i, part in enumerate(parts):
            if 'gravitee' in part:
                return parts[i-1].lower()
    except Exception as e:
        logging.error(f"Error parsing URL for customer ID: {e}")
        return "default"
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
                    'customer_name': row['customer_name'].strip(),
                    'api_token': row.get('api_token', os.getenv("GRAVITEE_API_TOKEN", "")).strip()
                })
        logging.info(f"Successfully loaded {len(customers)} customers from CSV")
        return customers
    except Exception as e:
        logging.error(f"Error reading customer CSV: {e}")
        raise

def fetch_apis(base_url, headers, session):
    """Fetch APIs using v2 endpoint with pagination"""
    all_apis = []
    base_url = get_v2_base_url(base_url.split('/management/')[0])

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

def fetch_api_pages(api_id, base_url, headers, session):
    """Fetch API documentation pages using V2 endpoint with enhanced processing"""
    try:
        url = f"{get_v2_base_url(base_url)}/apis/{api_id}/pages"
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

def fetch_api_details(api_id, base_url, headers, session):
    """Fetch detailed API information"""
    try:
        url = f"{get_v2_base_url(base_url)}/apis/{api_id}"
        logging.info(f"Fetching API details from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch API details for {api_id}: {e}")
        return {}

def fetch_api_subscriptions(api_id, base_url, headers, session):
    """Fetch API subscriptions"""
    try:
        url = f"{get_v2_base_url(base_url)}/apis/{api_id}/subscriptions?status=ACCEPTED,CLOSED,PAUSED,PENDING,REJECTED,RESUMED"
        logging.info(f"Fetching API subscriptions from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data.get("data", [])
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch subscriptions for API {api_id}: {e}")
        return []

def fetch_api_alerts(api_id, base_url, headers, session):
    """Fetch API alerts using V1 endpoint"""
    try:
        url = f"{get_v1_base_url(base_url)}/apis/{api_id}/alerts"
        logging.info(f"Fetching API alerts from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch alerts for API {api_id}: {e}")
        return []

def fetch_applications(base_url, headers, session):
    """Fetch applications using V1 endpoint"""
    try:
        url = f"{get_v1_base_url(base_url)}/applications"
        logging.info(f"Fetching applications from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch applications: {e}")
        return []

def fetch_app_subscriptions(app_id, base_url, headers, session):
    """Fetch application subscriptions using V1 endpoint"""
    try:
        url = f"{get_v1_base_url(base_url)}/applications/{app_id}/subscribed"
        logging.info(f"Fetching app subscriptions from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch subscriptions for app {app_id}: {e}")
        return []

def fetch_app_alerts(app_id, base_url, headers, session):
    """Fetch application alerts using V1 endpoint"""
    try:
        url = f"{get_v1_base_url(base_url)}/applications/{app_id}/alerts"
        logging.info(f"Fetching app alerts from: {url}")
        response = session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch alerts for app {app_id}: {e}")
        return []

def fetch_users(base_url, headers, session):
    """Fetch users using V1 endpoint with pagination"""
    all_users = []
    page = 1
    per_page = 20

    while True:
        try:
            url = f"{get_v1_base_url(base_url)}/users?page={page}&size={per_page}"
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

def fetch_gko_apis(base_url, headers, session):
    """Fetch GKO-managed APIs using V1 endpoint"""
    try:
        url = f"{get_v1_base_url(base_url)}/apis"
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

def fetch_dictionaries(base_url, headers, session):
    """Fetch dictionaries using V1 endpoint"""
    try:
        url = f"{get_v1_base_url(base_url)}/configuration/dictionaries"
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
                "configuration": policy.get("configuration", {}),
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
                "configuration": policy.get("configuration", {}),
                "description": policy.get("description", "")
            }
            flow_policies["post_policies"].append(policy_info)

        flow_policies["unique_policies"] = list(unique_policies)
        policies_info.append(flow_policies)

    return policies_info

def process_api_details(api_id, api_name, api_details, collected_data, base_url, headers, session):
    """Process details for a single API with enhanced documentation handling"""
    try:
        # Initialize API data structure
        api_data = {
            "name": api_name,
            "version": api_details.get("apiVersion", "unknown"),
            "type": api_details.get("type", "unknown"),
            "plans": {
                "count_per_type": {},
                "total": 0
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
            "entrypoints": []
        }

        # Process dictionaries
        try:
            dictionaries = fetch_dictionaries(base_url, headers, session)
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
            documentation = fetch_api_pages(api_id, base_url, headers, session)
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

        # Process plans
        plans = api_details.get("plans", [])
        plan_type_counts = {}
        for plan in plans:
            plan_type = plan.get("security", "unknown").lower()
            plan_type_counts[plan_type] = plan_type_counts.get(plan_type, 0) + 1

            plan_flows = plan.get("flows", [])
            if plan_flows:
                plan_policies = extract_policies_from_flows(
                    plan_flows,
                    plan_name=plan.get("name", "unknown"),
                    plan_security=plan.get("security", "unknown")
                )
                api_data["design"]["policies_per_flow"].extend(plan_policies)

        api_data["plans"]["count_per_type"] = plan_type_counts
        api_data["plans"]["total"] = len(plans)

        # Process subscriptions
        subscriptions = fetch_api_subscriptions(api_id, base_url, headers, session)
        api_data["subscriptions"]["count"] = len(subscriptions)

        # Process alerts
        alerts = fetch_api_alerts(api_id, base_url, headers, session)
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
        entrypoints = api_details.get("entrypoints", [])
        api_data["entrypoints"] = [{
            "type": entrypoint.get("type", "default"),
            "target": entrypoint.get("target", "unknown"),
            "tags": entrypoint.get("tags", []),
            "inherit": entrypoint.get("inherit", True)
        } for entrypoint in entrypoints]

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

                if not customer['api_token']:
                    logging.error(f"No API token available for customer {customer['customer_name']}")
                    continue

                headers = {"Authorization": f"Basic {customer['api_token']}"}

                # Initialize data collection
                # Initialize data collection structure
                collected_data = {
                    "customer_info": {
                        "customer_id": get_customer_id(customer['gravitee_url']),
                        "customer_name": customer['customer_name'],
                        "gravitee_url": customer['gravitee_url'],
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
                    gko_apis = fetch_gko_apis(customer['gravitee_url'], headers, session)
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
                    users = fetch_users(customer['gravitee_url'], headers, session)
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
                    applications = fetch_applications(customer['gravitee_url'], headers, session)
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
                            subscriptions = fetch_app_subscriptions(app_id, customer['gravitee_url'], headers, session)
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
                            alerts = fetch_app_alerts(app_id, customer['gravitee_url'], headers, session)
                            app_data["alerts"]["count"] = len(alerts)
                        except Exception as e:
                            logging.error(f"Error processing alerts for app {app_id}: {e}")

                        collected_data["applications"]["details"][app_id] = app_data
                        logging.info(f"Processed application: {app_data['name']} (ID: {app_id})")

                except Exception as e:
                    logging.error(f"Error processing applications for {customer['customer_name']}: {e}")

                # Fetch and process APIs
                apis = fetch_apis(customer['gravitee_url'], headers, session)
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
                        api_details = fetch_api_details(api_id, customer['gravitee_url'], headers, session)
                        if not api_details:
                            logging.error(f"Could not fetch details for API {api_id}")
                            continue

                        # Process API details
                        collected_data = process_api_details(
                            api_id,
                            api_name,
                            api_details,
                            collected_data,
                            customer['gravitee_url'],
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

                        # Save main data file
                        filename = f"{output_dir}/gravitee_data_{customer_id}_{timestamp}.json"
                        with open(filename, 'w', encoding='utf-8') as f:
                            json.dump(collected_data, f, indent=2, ensure_ascii=False)
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
