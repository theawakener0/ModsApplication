import os
import logging
import json # Added for json operations
import requests # Ensure requests is imported (already used elsewhere)
from datetime import datetime
# Import render_template, redirect, url_for
from flask import Flask, request, jsonify, render_template, redirect, url_for
# Removed: import ipinfo # No longer using the ipinfo library
from dotenv import load_dotenv # For loading .env file

# --- Load Environment Variables ---
load_dotenv()

# --- Configuration ---
LOG_FILE = os.getenv('LOG_FILE', 'visitor_log.txt')
LOG_LEVEL_STR = os.getenv('LOG_LEVEL', 'INFO').upper()
SECRET_KEY = os.getenv('SECRET_KEY') or os.urandom(24)
IPINFO_TOKEN = os.getenv('IPINFO_TOKEN', None)
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL', None) # Added for Discord webhook
SECOND_DISCORD_WEBHOOK_URL = os.getenv('SECOND_DISCORD_WEBHOOK_URL', None) # Added for the second webhook
APPLICATIONS_FILE = os.getenv('APPLICATIONS_FILE', 'applications.json') # Added for storing applications
HOST = os.getenv('HOST', '127.0.0.1')
PORT = int(os.getenv('PORT', 5000))
DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')
DISCORD_BOT_TOKEN= os.getenv("DISCORD_BOT_TOKEN")

# --- Map Log Level String to Logging Constant ---
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}
LOG_LEVEL = LOG_LEVELS.get(LOG_LEVEL_STR, logging.INFO)

# --- Flask App Initialization ---
app = Flask(__name__) # Flask automatically looks for the 'templates' folder
app.secret_key = SECRET_KEY

# --- Logging Setup ---
log_dir = os.path.dirname(LOG_FILE)
if log_dir and not os.path.exists(log_dir):
    try:
        os.makedirs(log_dir)
    except OSError as e:
        print(f"Error creating log directory '{log_dir}': {e}")
        LOG_FILE = os.path.basename(LOG_FILE) if log_dir else 'visitor_log.txt'
        print(f"Warning: Logging to '{LOG_FILE}' in the current directory instead.")

try:
    LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    app.logger.setLevel(LOG_LEVEL) # Ensure app.logger is configured before adding handlers
    # Check if handlers are already added to prevent duplication if this code runs multiple times (e.g. reloader)
    if not any(isinstance(h, logging.FileHandler) and h.baseFilename == file_handler.baseFilename for h in app.logger.handlers):
        app.logger.addHandler(file_handler)
    app.logger.propagate = False
except IOError as e:
    print(f"Error setting up file logger for '{LOG_FILE}': {e}")
    print("Logging may not work correctly.")

def get_ip_info(ip_address, api_token):
    """Fetches comprehensive geolocation data for an IP address using the ipinfo.io API directly.

    Args:
        ip_address (str): The IP address to look up.
        api_token (str): The ipinfo.io API token (can be None for basic info).

    Returns:
        dict or None: A dictionary containing IP information, or None on error.
    """
    if not ip_address:
        app.logger.warning("get_ip_info called with no IP address.")
        return None

    try:
        url = f"https://ipinfo.io/{ip_address}/json"
        params = {}
        if api_token:
            params['token'] = api_token

        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        details = response.json()
        app.logger.debug(f"Successfully fetched IP info for {ip_address} using direct API call to ipinfo.io.")
        return details
    except requests.exceptions.Timeout:
        app.logger.error(f"Timeout fetching IP info for {ip_address} from ipinfo.io API.")
        return None
    except requests.exceptions.HTTPError as e:
        app.logger.error(f"HTTP error fetching IP info for {ip_address} from ipinfo.io API: {e.response.status_code} {e.response.reason}")
        return None
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching IP info for {ip_address} from ipinfo.io API: {e}", exc_info=True)
        return None
    except json.JSONDecodeError as e:
        app.logger.error(f"Error decoding JSON response from ipinfo.io API for {ip_address}: {e}", exc_info=True)
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error fetching IP info for {ip_address} using direct API call: {e}", exc_info=True)
        return None

# --- Helper Functions ---
def get_discord_avatar_url(discord_id):
    """Fetches the avatar URL for a Discord user by their ID using the Discord API."""
    if not discord_id:
        return None
    if not DISCORD_BOT_TOKEN: # Check if bot token is available
        app.logger.warning("DISCORD_BOT_TOKEN not set. Cannot fetch Discord avatar.")
        return None
    try:
        url = f"https://discord.com/api/v10/users/{discord_id}"
        headers = {"User-Agent": "IPLoggerBot/1.0", "Accept": "application/json", "Authorization": f"Bot {DISCORD_BOT_TOKEN}"} # Corrected header
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        user_data = response.json()
        avatar_hash = user_data.get("avatar")
        if avatar_hash:
            # Construct the full URL. Discord handles GIF avatars automatically with .png extension request.
            # See: https://discord.com/developers/docs/reference#image-formatting
            return f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.png?size=128" # Request a reasonable size
        else:
            # Handle users with default avatars (no hash)
            # Default avatars depend on the discriminator modulo 5
            # It's simpler to let Discord handle this by not providing a thumbnail if no hash exists,
            # or you could implement the default avatar logic if required.
            # For now, return None if no custom avatar.
            return None
    except Exception as e:
        app.logger.error(f"Failed to fetch Discord avatar URL for {discord_id}: {e}", exc_info=True)
        return None

def save_application(data):
    """Appends application data to the JSON file.

    Args:
        data (dict): A dictionary containing the application data, including
                     new fields like 'real_name', 'email', 'phone', 'discord_id'.

    Returns:
        bool: True if saving was successful, False otherwise.
    """
    try:
        # Ensure the directory exists only if a path is specified
        dir_path = os.path.dirname(APPLICATIONS_FILE)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        # Read existing data or initialize if file doesn't exist/is empty
        try:
            with open(APPLICATIONS_FILE, 'r', encoding='utf-8') as f: # Specify encoding
                applications = json.load(f)
                if not isinstance(applications, list): # Ensure it's a list
                    app.logger.warning(f"File {APPLICATIONS_FILE} did not contain a valid JSON list. Initializing as empty list.")
                    applications = []
        except FileNotFoundError:
            app.logger.info(f"File {APPLICATIONS_FILE} not found. Creating a new one.")
            applications = []
        except json.JSONDecodeError:
            app.logger.error(f"Error decoding JSON from {APPLICATIONS_FILE}. Initializing as empty list.")
            applications = [] # Reset if file is corrupted

        # Append new data (ensure all expected keys are present, even if empty)
        # This makes the structure consistent across all entries
        application_entry = {
            'real_name': data.get('real_name', 'N/A'),
            'email': data.get('email', 'N/A'),
            'phone': data.get('phone', ''), # Optional
            'discord_id': data.get('discord_id', ''), # Optional
            'discord_username': data.get('discord_username', 'N/A'),
            'age': data.get('age', 'N/A'),
            'timezone': data.get('timezone', 'N/A'),
            'experience': data.get('experience', 'N/A'),
            'reason': data.get('reason', 'N/A'),
            'availability': data.get('availability', 'N/A'),
            'scenario': data.get('scenario', 'N/A'),
            'anything_else': data.get('anything_else', ''), # Optional
            'timestamp': data.get('timestamp', 'N/A'),
            'ip_address': data.get('ip_address', 'N/A'),
            'user_agent': data.get('user_agent', 'N/A')
        }
        applications.append(application_entry)

        # Write back to file
        with open(APPLICATIONS_FILE, 'w', encoding='utf-8') as f: # Specify encoding
            json.dump(applications, f, indent=4, ensure_ascii=False) # ensure_ascii=False for wider character support
        app.logger.info(f"Application from {data.get('discord_username', 'N/A')} saved to {APPLICATIONS_FILE}")
        return True
    except IOError as e:
        app.logger.error(f"IOError saving application to {APPLICATIONS_FILE}: {e}", exc_info=True)
    except Exception as e:
        app.logger.error(f"Unexpected error saving application: {e}", exc_info=True)
    return False

def send_to_discord(data, webhook_url):
    """Sends formatted application data to a Discord webhook."""
    if not webhook_url:
        app.logger.warning("DISCORD_WEBHOOK_URL not set. Skipping Discord notification.")
        return False

    # Enhanced formatting for Discord embed
    discord_id = data.get('discord_id')
    discord_username = data.get('discord_username', 'N/A')
    user_mention = f"<@{discord_id}>" if discord_id else discord_username # Mention user if ID is available

    # Fetch avatar URL from Discord API if Discord ID is present
    avatar_url = None
    if discord_id:
        avatar_url = get_discord_avatar_url(discord_id)
        # Store it back in data if needed elsewhere, though maybe not necessary now
        # if avatar_url:
        #     data['avatar_url'] = avatar_url # Or store hash if preferred


    embed = {
        "title": "New Moderator Application Received!",
        "description": f"Application from: {user_mention}", # Mention the user
        "color": 5793266, # Discord Blurple
        "fields": [
            {"name": "Real Name", "value": data.get('real_name', 'N/A'), "inline": True},
            {"name": "Email", "value": data.get('email', 'N/A'), "inline": True},
            {"name": "Phone", "value": data.get('phone', '_Not Provided_'), "inline": True},
            {"name": "Discord Username", "value": discord_username, "inline": True},
            {"name": "Discord ID", "value": discord_id if discord_id else '_Not Provided_', "inline": True},
            {"name": "Age", "value": str(data.get('age', 'N/A')), "inline": True},
            {"name": "Timezone", "value": data.get('timezone', 'N/A'), "inline": True},
            {"name": "Availability (hrs/week)", "value": str(data.get('availability', 'N/A')), "inline": True},
            # Keep longer fields non-inline, truncate to avoid Discord limits
            {"name": "Experience", "value": str(data.get('experience', 'N/A'))[:1020] + ('...' if len(str(data.get('experience', 'N/A'))) > 1020 else ''), "inline": False},
            {"name": "Reason for Applying", "value": str(data.get('reason', 'N/A'))[:1020] + ('...' if len(str(data.get('reason', 'N/A'))) > 1020 else ''), "inline": False},
            {"name": "Scenario Response", "value": str(data.get('scenario', 'N/A'))[:1020] + ('...' if len(str(data.get('scenario', 'N/A'))) > 1020 else ''), "inline": False},
            {"name": "Anything Else", "value": str(data.get('anything_else', '_None_'))[:1020] + ('...' if len(str(data.get('anything_else', '_None_'))) > 1020 else ''), "inline": False},
            {"name": "Timestamp", "value": data.get('timestamp', 'N/A'), "inline": False},
            # Optional: Add IP/User Agent if needed, but be mindful of privacy
            # {"name": "Submitter IP", "value": data.get('ip_address', 'N/A'), "inline": True},
            # {"name": "User Agent", "value": data.get('user_agent', 'N/A'), "inline": False},
        ],
        "footer": {"text": f"Application submitted via Web Form"},
        "thumbnail": {"url": avatar_url} if avatar_url else None
    }

    payload = {
        "embeds": [embed]
    }

    headers = {'Content-Type': 'application/json'}

    try:
        response = requests.post(webhook_url, headers=headers, json=payload, timeout=15)
        response.raise_for_status() # Raise exception for bad status codes (4xx or 5xx)
        app.logger.info(f"Successfully sent application from {data.get('discord_username', 'N/A')} to Discord.")
        return True
    except requests.exceptions.Timeout:
        app.logger.error(f"Timeout sending application to Discord webhook {webhook_url}")
    except requests.exceptions.HTTPError as e:
        app.logger.error(f"HTTP error sending application to Discord: {e.response.status_code} {e.response.reason}")
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Request error sending application to Discord: {e}")
    except Exception as e:
        app.logger.error(f"Unexpected error sending application to Discord: {e}", exc_info=True)
    return False

def send_detailed_log_to_discord(log_details, application_data=None, webhook_url=None):
    """Sends detailed log information (IP, User-Agent, Geo, ASN, etc.) and optional application data to a Discord webhook.

    Args:
        log_details (dict): Dictionary containing log info. Expected keys:
                            'ip_address', 'user_agent', 'ip_details' (dict from ipinfo.io), 'timestamp'.
        application_data (dict, optional): Data from a submitted application.
        webhook_url (str, optional): Specific webhook URL to use, otherwise defaults to SECOND_DISCORD_WEBHOOK_URL.
    """
    target_webhook_url = webhook_url or SECOND_DISCORD_WEBHOOK_URL
    if not target_webhook_url:
        app.logger.warning("Second Discord webhook URL not set. Skipping detailed log notification.")
        return False

    ip_address = log_details.get('ip_address', 'N/A')
    user_agent = log_details.get('user_agent', 'N/A')
    ip_details_dict = log_details.get('ip_details') # This is now a dictionary
    timestamp = log_details.get('timestamp', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))

    # Initialize all IP information strings
    geo_string = "_Not Available_"
    asn_string = "_Not Available_"
    carrier_string = "_Not Available_"
    company_string = "_Not Available_"
    privacy_string = "_Not Available_"
    hostname_str = "_Not Available_"
    anycast_str = "_Not Available_"
    postal_str = "_Not Available_"
    abuse_str = "_Not Available_"
    domains_str = "_Not Available_"

    if ip_details_dict: # Check if ip_details_dict is not None
        # --- Format Geo Info ---
        geo_parts = []
        city = ip_details_dict.get('city')
        region = ip_details_dict.get('region')
        country_name = ip_details_dict.get('country_name') # ipinfo.io often returns 'country_name'
        if not country_name: # Fallback to 'country' if 'country_name' is not present
            country_code = ip_details_dict.get('country')
            # You might want a mapping from country code to name if only code is available
            country_name = country_code # Or use a mapping like pycountry if full name is critical
        
        loc = ip_details_dict.get('loc')
        org_isp = ip_details_dict.get('org')
        ip_timezone = ip_details_dict.get('timezone')

        if city: geo_parts.append(city)
        if region: geo_parts.append(region)
        if country_name: geo_parts.append(country_name)
        geo_string = ", ".join(filter(None, geo_parts))
        if loc: geo_string += f" (Loc: {loc})"
        if ip_timezone: geo_string += f" (Timezone: {ip_timezone})"
        if org_isp: geo_string += f" (ISP: {org_isp})"
        if not geo_string: geo_string = "_Details Unavailable_"

        # --- Format ASN Info ---
        asn_details = ip_details_dict.get('asn', {})
        asn_id = asn_details.get('asn')
        asn_name = asn_details.get('name')
        asn_domain = asn_details.get('domain')
        asn_route = asn_details.get('route')
        asn_type = asn_details.get('type')
        asn_parts = []
        if asn_id: asn_parts.append(f"ID: {asn_id}")
        if asn_name: asn_parts.append(f"Name: {asn_name}")
        if asn_domain: asn_parts.append(f"Domain: {asn_domain}")
        if asn_route: asn_parts.append(f"Route: {asn_route}")
        if asn_type: asn_parts.append(f"Type: {asn_type}")
        asn_string = ", ".join(filter(None, asn_parts)) if asn_parts else "_Not Available_"

        # --- Format Carrier Info ---
        carrier_details = ip_details_dict.get('carrier', {})
        carrier_name = carrier_details.get('name')
        carrier_mcc = carrier_details.get('mcc')
        carrier_mnc = carrier_details.get('mnc')
        carrier_parts = []
        if carrier_name: carrier_parts.append(f"Name: {carrier_name}")
        if carrier_mcc: carrier_parts.append(f"MCC: {carrier_mcc}")
        if carrier_mnc: carrier_parts.append(f"MNC: {carrier_mnc}")
        carrier_string = ", ".join(filter(None, carrier_parts)) if carrier_parts else "_Not Available_"
        
        # --- Format Company Info ---
        company_details = ip_details_dict.get('company', {})
        company_name = company_details.get('name')
        company_domain = company_details.get('domain')
        company_type = company_details.get('type')
        company_parts = []
        if company_name: company_parts.append(f"Name: {company_name}")
        if company_domain: company_parts.append(f"Domain: {company_domain}")
        if company_type: company_parts.append(f"Type: {company_type}")
        company_string = ", ".join(filter(None, company_parts)) if company_parts else "_Not Available_"

        # --- Format Privacy Info ---
        privacy_details = ip_details_dict.get('privacy', {})
        vpn = privacy_details.get('vpn', False)
        proxy = privacy_details.get('proxy', False)
        tor = privacy_details.get('tor', False)
        relay = privacy_details.get('relay', False) # Changed from 'hosting' to 'relay' as per common ipinfo fields
        hosting = privacy_details.get('hosting', False) # Added hosting, as it's a common field
        service = privacy_details.get('service', '')

        privacy_parts = []
        if vpn: privacy_parts.append("VPN")
        if proxy: privacy_parts.append("Proxy")
        if tor: privacy_parts.append("Tor")
        if relay: privacy_parts.append("Relay")
        if hosting: privacy_parts.append("Hosting")
        if service: privacy_parts.append(f"Service: {service}")
        privacy_string = ", ".join(filter(None, privacy_parts)) if privacy_parts else "None Detected"
        if not privacy_string and not any([vpn, proxy, tor, relay, hosting]): # if all flags are false
             privacy_string = "Standard Connection (No VPN/Proxy/Tor/Relay/Hosting Detected)"


        # --- Other details ---
        hostname_str = ip_details_dict.get('hostname', '_Not Available_')
        anycast_str = "Yes" if ip_details_dict.get('anycast') else "No"
        postal_str = ip_details_dict.get('postal', '_Not Available_')

        # --- Abuse Contact ---
        abuse_details = ip_details_dict.get('abuse', {})
        abuse_address = abuse_details.get('address')
        abuse_country = abuse_details.get('country')
        abuse_email = abuse_details.get('email')
        abuse_name = abuse_details.get('name')
        abuse_network = abuse_details.get('network')
        abuse_phone = abuse_details.get('phone')
        abuse_parts = []
        if abuse_address: abuse_parts.append(f"Address: {abuse_address}")
        # Add other abuse fields as needed, be mindful of length
        if abuse_email: abuse_parts.append(f"Email: {abuse_email}")
        if abuse_name: abuse_parts.append(f"Name: {abuse_name}")
        abuse_str = "; ".join(filter(None, abuse_parts)) if abuse_parts else "_Not Available_"


        # --- Domains ---
        # The 'domains' field from ipinfo.io is usually a more complex object.
        # Example: "domains": {"ip": "8.8.8.8", "total": 5, "domains": ["domain1.com", ...]}
        # For simplicity, let's try to get the list of domains if available.
        domains_data = ip_details_dict.get('domains')
        if isinstance(domains_data, dict) and 'domains' in domains_data and isinstance(domains_data['domains'], list):
            domains_list = domains_data['domains'][:5] # Get up to 5 domains
            if domains_list:
                domains_str = ", ".join(domains_list)
                if domains_data.get('total', 0) > 5:
                    domains_str += f", ... (Total: {domains_data['total']})"
            else:
                domains_str = "_No Domains Listed_"
        elif isinstance(domains_data, list): # Simpler list format (less common from ipinfo direct)
            domains_list = domains_data[:5]
            if domains_list:
                domains_str = ", ".join(domains_list)
            else:
                domains_str = "_No Domains Listed_"
        else:
            domains_str = "_Not Available or Invalid Format_"

    # --- Base Embed for Log Details ---
    embed_fields = [
        {"name": "Timestamp", "value": timestamp, "inline": False},
        {"name": "IP Address", "value": ip_address, "inline": True},
        {"name": "User Agent", "value": user_agent[:1020] + ('...' if len(user_agent) > 1020 else ''), "inline": False},
        
        # IP Info fields (populated if ip_details_obj exists, otherwise shows "_Not Available_")
        {"name": "Geolocation", "value": geo_string, "inline": False},
        {"name": "Hostname", "value": hostname_str, "inline": False},
        {"name": "Anycast", "value": anycast_str, "inline": True},
        {"name": "Postal Code", "value": postal_str, "inline": True},
        {"name": "ASN Details", "value": asn_string, "inline": False},
        {"name": "Company", "value": company_string, "inline": True},
        {"name": "Carrier", "value": carrier_string, "inline": True},
        {"name": "Privacy Flags", "value": privacy_string, "inline": False},
        {"name": "Abuse Contact", "value": abuse_str, "inline": False},
        {"name": "Associated Domains (up to 5)", "value": domains_str, "inline": False}, # Clarified domain limit in title
    ]
    
    embed = {
        "title": "Visitor Log / Event",
        "color": 3447003, # Discord Blue
        "fields": embed_fields,
        "footer": {"text": "Detailed Log Event"}
    }

    # --- Add Application Details if provided ---
    if application_data:
        embed["title"] = "New Application Submission & Log"
        embed["color"] = 5793266 # Discord Blurple for applications
        discord_id = application_data.get('discord_id')
        discord_username = application_data.get('discord_username', 'N/A')
        user_mention = f"<@{discord_id}>" if discord_id else discord_username

        # Fetch avatar URL from Discord API if Discord ID is present
        avatar_url = None
        if discord_id:
            avatar_url = get_discord_avatar_url(discord_id)
            # Store it back in application_data if needed elsewhere
            # if avatar_url:
            #    application_data['avatar_url'] = avatar_url

        app_fields = [
            {"name": "\n--- Application Details ---", "value": f"Submitted by: {user_mention}", "inline": False},
            {"name": "Real Name", "value": application_data.get('real_name', 'N/A'), "inline": True},
            {"name": "Email", "value": application_data.get('email', 'N/A'), "inline": True},
            {"name": "Discord ID", "value": discord_id if discord_id else '_Not Provided_', "inline": True},
            {"name": "Phone", "value": application_data.get('phone', '_Not Provided_'), "inline": True},
            # Provide a snippet for potentially long text fields from application_data
            {"name": "Reason Snippet", "value": str(application_data.get('reason', 'N/A'))[:100] + ('...' if len(str(application_data.get('reason', 'N/A'))) > 100 else ''), "inline": False},
        ]
        # Insert application fields after the standard log fields
        embed["fields"].extend(app_fields)
        if avatar_url:
            embed["thumbnail"] = {"url": avatar_url}
        embed["footer"]["text"] = "Application Submission Log"

    payload = {
        "embeds": [embed]
    }
    headers = {'Content-Type': 'application/json'}

    try:
        response = requests.post(target_webhook_url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        app.logger.info(f"Successfully sent detailed log for IP {ip_address} to second Discord webhook.")
        return True
    except requests.exceptions.Timeout:
        app.logger.error(f"Timeout sending detailed log to second Discord webhook {target_webhook_url}")
    except requests.exceptions.HTTPError as e:
        app.logger.error(f"HTTP error sending detailed log to second Discord: {e.response.status_code} {e.response.reason}")
        # Log response body if available for debugging
        try:
            error_details = e.response.json()
            app.logger.error(f"Discord API Error Response: {error_details}")
        except json.JSONDecodeError:
            app.logger.error(f"Discord API Error Response (non-JSON): {e.response.text}")
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Request error sending detailed log to second Discord: {e}")
    except Exception as e:
        app.logger.error(f"Unexpected error sending detailed log to second Discord: {e}", exc_info=True)
    return False

# --- Routes --- #
@app.route('/')
def index():
    """Logs visitor IP and serves the application form."""
    # Get IP Address (considering proxies)
    if request.headers.getlist("X-Forwarded-For"):
        ip_address = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    else:
        ip_address = request.remote_addr

    user_agent = request.headers.get('User-Agent', 'Unknown')
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    # Get IP Details using the direct API call - now returns a dict
    ip_details_dict = get_ip_info(ip_address, IPINFO_TOKEN)
    
    # For logging, convert dict to JSON string or handle None
    geo_string_for_log = json.dumps(ip_details_dict) if ip_details_dict else "IP Details Unavailable"

    # Log the visit
    log_message = f"IP: {ip_address}, User-Agent: {user_agent}, Geo: {geo_string_for_log}"
    app.logger.info(f"Visit to /: {log_message}")

    # Send detailed log to the second webhook
    # Pass the ip_details_dict dictionary directly
    log_details_payload = {
        'ip_address': ip_address,
        'user_agent': user_agent,
        'ip_details': ip_details_dict, # Pass the dictionary
        'timestamp': timestamp
    }
    send_detailed_log_to_discord(log_details_payload)

    # Serve the application form
    return render_template('mod_application.html')

@app.route('/apply', methods=['POST'])
def handle_application():
    """Handles the submission of the moderator application form."""
    # Get IP Address (considering proxies)
    if request.headers.getlist("X-Forwarded-For"):
        ip_address = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    else:
        ip_address = request.remote_addr

    user_agent = request.headers.get('User-Agent', 'Unknown')
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    # Get IP Details using the direct API call - now returns a dict
    ip_details_dict = get_ip_info(ip_address, IPINFO_TOKEN)
    geo_string_for_log = json.dumps(ip_details_dict) if ip_details_dict else "IP Details Unavailable"

    # Log the submission attempt
    log_message = f"IP: {ip_address}, User-Agent: {user_agent}, Geo: {geo_string_for_log}"
    app.logger.info(f"Application submission attempt from: {log_message}")

    # Extract form data
    application_data = {
        'real_name': request.form.get('real_name'),
        'email': request.form.get('email'),
        'phone': request.form.get('phone', ''), # Optional
        'discord_id': request.form.get('discord_id'),
        'discord_username': request.form.get('discord_username'),
        'age': request.form.get('age'),
        'timezone': request.form.get('timezone'),
        'experience': request.form.get('experience'),
        'reason': request.form.get('reason'),
        'availability': request.form.get('availability'),
        'scenario': request.form.get('scenario'),
        'anything_else': request.form.get('anything_else', ''), # Optional
        'timestamp': timestamp,
        'ip_address': ip_address,
        'user_agent': user_agent
    } # Corrected missing closing brace

    # Save the application data
    if save_application(application_data):
        # Send application details to the primary webhook
        send_to_discord(application_data, DISCORD_WEBHOOK_URL)

        # Send detailed log + application context to the second webhook
        # Pass the ip_details_dict dictionary directly
        log_details_payload = {
            'ip_address': ip_address,
            'user_agent': user_agent,
            'ip_details': ip_details_dict, # Pass the dictionary
            'timestamp': timestamp
        }
        send_detailed_log_to_discord(log_details_payload, application_data=application_data)

        # Redirect to a success page
        return redirect(url_for('application_submitted'))
    else:
        # Handle saving error (e.g., show an error message)
        app.logger.error("Failed to save application data.")
        # You might want to render an error template or flash a message
        return "An error occurred while processing your application. Please try again later.", 500

@app.route('/submitted')
def application_submitted():
    """Displays the application submitted confirmation page."""
    return render_template('application_submitted.html')

# --- API Endpoint (Optional - Example) ---
@app.route('/log', methods=['POST'])
def log_ip():
    """API endpoint to log IP address and potentially other data."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    ip_address = data.get('ip') # IP from JSON payload
    user_agent = data.get('user_agent', request.headers.get('User-Agent', 'Unknown'))
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    if not ip_address:
        # Try to get from request headers if not provided in JSON
        if request.headers.getlist("X-Forwarded-For"):
            ip_address = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
        else:
            ip_address = request.remote_addr

    # Get IP Details using the direct API call - now returns a dict
    ip_details_dict = get_ip_info(ip_address, IPINFO_TOKEN)
    geo_string_for_log = json.dumps(ip_details_dict) if ip_details_dict else "IP Details Unavailable"

    # Log the information
    log_message = f"API Log - IP: {ip_address}, User-Agent: {user_agent}, Geo: {geo_string_for_log}, Data: {json.dumps(data)}"
    app.logger.info(log_message)

    # Send detailed log to the second webhook
    # Pass the ip_details_dict dictionary directly
    log_details_payload = {
        'ip_address': ip_address,
        'user_agent': user_agent,
        'ip_details': ip_details_dict, # Pass the dictionary
        'timestamp': timestamp
    }
    send_detailed_log_to_discord(log_details_payload, application_data=data)

    return jsonify({"status": "logged", "ip": ip_address}), 200

# --- Main Execution --- #
if __name__ == '__main__':
    print(f"Starting Flask server on {HOST}:{PORT}...")
    print(f"Debug mode: {DEBUG}")
    print(f"Logging to: {LOG_FILE} at level {LOG_LEVEL_STR}")
    if not DISCORD_WEBHOOK_URL:
        print("Warning: DISCORD_WEBHOOK_URL is not set in .env file. Application Discord notifications will be skipped.")
    if not SECOND_DISCORD_WEBHOOK_URL:
        print("Warning: SECOND_DISCORD_WEBHOOK_URL is not set in .env file. Detailed log Discord notifications will be skipped.")
    if not IPINFO_TOKEN:
        print("Warning: IPINFO_TOKEN is not set in .env file. Geolocation lookups will be limited or may fail.")
    if not os.path.exists(APPLICATIONS_FILE):
        print(f"Warning: Applications file '{APPLICATIONS_FILE}' does not exist. It will be created on first submission.")

    # Use waitress for production, or Flask's dev server if DEBUG is True
    if not DEBUG:
        try:
            from waitress import serve
            print("Running in production mode using Waitress.")
            serve(app, host=HOST, port=PORT)
        except ImportError:
            print("Waitress not found. Falling back to Flask's development server.")
            print("For production deployments, please install Waitress: pip install waitress")
            app.run(host=HOST, port=PORT, debug=False) # Explicitly set debug=False
    else:
        print("Running in development mode with Flask's built-in server.")
        app.run(host=HOST, port=PORT, debug=True)

