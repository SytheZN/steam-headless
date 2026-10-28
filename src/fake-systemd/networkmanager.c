#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "fake-systemd.h"

#define MAX_NAMESERVERS 4

#define PATH_ROOT               "/"
#define PATH_NETWORK_MANAGER    "/org/freedesktop/NetworkManager"
#define PATH_DEVICE             "/org/freedesktop/NetworkManager/Devices/1"
#define PATH_ACTIVE_CONNECTION  "/org/freedesktop/NetworkManager/ActiveConnection/1"
#define PATH_SETTINGS           "/org/freedesktop/NetworkManager/Settings"
#define PATH_CONNECTION         "/org/freedesktop/NetworkManager/Settings/1"
#define PATH_IP4_CONFIG         "/org/freedesktop/NetworkManager/IP4Config/1"

#define ERROR_INVALID_CONNECTION "org.freedesktop.NetworkManager.Settings.InvalidConnection"

#define CONNECTION_UUID         "6c1f8a4e-2b7d-4c3a-9e51-0d2f7a9b3c11"
#define CONNECTION_ID           "Wired connection 1"
#define CONNECTION_TYPE         "802-3-ethernet"

#define FALLBACK_INTERFACE      "eth0"
#define FALLBACK_ADDRESS        "0.0.0.0"
#define FALLBACK_MAC            "00:00:00:00:00:00"

#define CONST_PROPERTY SD_BUS_VTABLE_PROPERTY_CONST

#define GETTER_PARAMS \
    sd_bus *bus __attribute__((unused)), \
    const char *path __attribute__((unused)), \
    const char *interface __attribute__((unused)), \
    const char *property __attribute__((unused)), \
    sd_bus_message *reply, \
    void *userdata __attribute__((unused)), \
    sd_bus_error *error __attribute__((unused))

#define METHOD_PARAMS \
    sd_bus_message *message, \
    void *userdata __attribute__((unused)), \
    sd_bus_error *error __attribute__((unused))

struct host_info {
    char interface_name[IF_NAMESIZE];
    char mac[32];
    char address[INET_ADDRSTRLEN];
    uint32_t prefix;
    char gateway[INET_ADDRSTRLEN];
    char nameservers[MAX_NAMESERVERS][INET_ADDRSTRLEN];
    size_t nameserver_count;
    char hostname[256];
    char udi[96];
};

static struct host_info host;

static void discover_interface(void) {
    snprintf(host.interface_name, sizeof(host.interface_name), "%s", FALLBACK_INTERFACE);
    snprintf(host.address, sizeof(host.address), "%s", FALLBACK_ADDRESS);
    host.prefix = 0;

    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0)
        return;

    for (struct ifaddrs *entry = interfaces; entry; entry = entry->ifa_next) {
        if (!entry->ifa_addr || !entry->ifa_netmask)
            continue;
        if (entry->ifa_addr->sa_family != AF_INET)
            continue;
        if (entry->ifa_flags & IFF_LOOPBACK)
            continue;

        const struct sockaddr_in *address = (const struct sockaddr_in *)entry->ifa_addr;
        const struct sockaddr_in *netmask = (const struct sockaddr_in *)entry->ifa_netmask;

        snprintf(host.interface_name, sizeof(host.interface_name), "%s", entry->ifa_name);
        inet_ntop(AF_INET, &address->sin_addr, host.address, sizeof(host.address));
        host.prefix = (uint32_t)__builtin_popcount(netmask->sin_addr.s_addr);
        break;
    }

    freeifaddrs(interfaces);
}

static void discover_mac(void) {
    snprintf(host.mac, sizeof(host.mac), "%s", FALLBACK_MAC);

    char mac_path[128];
    snprintf(mac_path, sizeof(mac_path), "/sys/class/net/%s/address", host.interface_name);

    FILE *file = fopen(mac_path, "r");
    if (!file)
        return;

    char line[64];
    if (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] != '\0')
            snprintf(host.mac, sizeof(host.mac), "%s", line);
    }
    fclose(file);
}

static void discover_gateway(void) {
    host.gateway[0] = '\0';

    FILE *file = fopen("/proc/net/route", "r");
    if (!file)
        return;

    char line[256];
    bool header_line = true;
    while (fgets(line, sizeof(line), file)) {
        if (header_line) {
            header_line = false;
            continue;
        }

        char route_interface[IF_NAMESIZE];
        unsigned int destination = 0;
        unsigned int gateway = 0;
        if (sscanf(line, "%15s %x %x", route_interface, &destination, &gateway) != 3)
            continue;
        if (destination != 0 || gateway == 0)
            continue;

        struct in_addr gateway_address = { .s_addr = gateway };
        inet_ntop(AF_INET, &gateway_address, host.gateway, sizeof(host.gateway));
        break;
    }

    fclose(file);
}

static void discover_nameservers(void) {
    host.nameserver_count = 0;

    FILE *file = fopen("/etc/resolv.conf", "r");
    if (!file)
        return;

    char line[256];
    while (host.nameserver_count < MAX_NAMESERVERS && fgets(line, sizeof(line), file)) {
        char candidate[INET_ADDRSTRLEN];
        struct in_addr parsed;

        if (sscanf(line, "nameserver %15s", candidate) != 1)
            continue;
        if (inet_pton(AF_INET, candidate, &parsed) != 1)
            continue;

        snprintf(host.nameservers[host.nameserver_count], INET_ADDRSTRLEN, "%s", candidate);
        host.nameserver_count++;
    }

    fclose(file);
}

static void discover_hostname(void) {
    if (gethostname(host.hostname, sizeof(host.hostname)) != 0)
        host.hostname[0] = '\0';
    host.hostname[sizeof(host.hostname) - 1] = '\0';
}

static void discover_host(void) {
    discover_interface();
    discover_mac();
    discover_gateway();
    discover_nameservers();
    discover_hostname();
    snprintf(host.udi, sizeof(host.udi), "/sys/devices/virtual/net/%s", host.interface_name);

    logmsg("interface=%s address=%s/%u mac=%s gateway=%s hostname=%s",
           host.interface_name, host.address, host.prefix, host.mac,
           host.gateway[0] ? host.gateway : "(none)", host.hostname);
    for (size_t index = 0; index < host.nameserver_count; index++)
        logmsg("nameserver=%s", host.nameservers[index]);
}

static int append_empty_array(sd_bus_message *reply, const char *element_signature) {
    int result = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, element_signature);
    if (result < 0)
        return result;
    return sd_bus_message_close_container(reply);
}

#define DEFINE_BOOL_GETTER(function, value) \
    static int function(GETTER_PARAMS) { \
        int flag = (value); \
        return sd_bus_message_append_basic(reply, SD_BUS_TYPE_BOOLEAN, &flag); \
    }

#define DEFINE_U32_GETTER(function, value) \
    static int function(GETTER_PARAMS) { \
        uint32_t number = (value); \
        return sd_bus_message_append_basic(reply, SD_BUS_TYPE_UINT32, &number); \
    }

#define DEFINE_STRING_GETTER(function, value) \
    static int function(GETTER_PARAMS) { \
        const char *text = (value); \
        return sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, text); \
    }

#define DEFINE_PATH_GETTER(function, value) \
    static int function(GETTER_PARAMS) { \
        const char *object_path = (value); \
        return sd_bus_message_append_basic(reply, SD_BUS_TYPE_OBJECT_PATH, object_path); \
    }

#define DEFINE_SINGLE_PATH_LIST_GETTER(function, value) \
    static int function(GETTER_PARAMS) { \
        return sd_bus_message_append(reply, "ao", 1, (value)); \
    }

#define DEFINE_EMPTY_ARRAY_GETTER(function, element_signature) \
    static int function(GETTER_PARAMS) { \
        return append_empty_array(reply, (element_signature)); \
    }

DEFINE_BOOL_GETTER(get_true, 1)
DEFINE_BOOL_GETTER(get_false, 0)

DEFINE_U32_GETTER(get_u32_0, 0)
DEFINE_U32_GETTER(get_u32_1, 1)
DEFINE_U32_GETTER(get_u32_2, 2)
DEFINE_U32_GETTER(get_u32_3, 3)
DEFINE_U32_GETTER(get_u32_4, 4)
DEFINE_U32_GETTER(get_u32_70, 70)
DEFINE_U32_GETTER(get_u32_100, 100)
DEFINE_U32_GETTER(get_u32_1000, 1000)
DEFINE_U32_GETTER(get_u32_1500, 1500)
DEFINE_U32_GETTER(get_u32_interface_flags, 0x10003)

DEFINE_STRING_GETTER(get_empty_string, "")
DEFINE_STRING_GETTER(get_ethernet_type, CONNECTION_TYPE)
DEFINE_STRING_GETTER(get_nm_version, "1.52.0")
DEFINE_STRING_GETTER(get_driver_name, "veth")
DEFINE_STRING_GETTER(get_connection_id, CONNECTION_ID)
DEFINE_STRING_GETTER(get_connection_uuid, CONNECTION_UUID)
DEFINE_STRING_GETTER(get_udi, host.udi)
DEFINE_STRING_GETTER(get_interface_name, host.interface_name)
DEFINE_STRING_GETTER(get_mac, host.mac)
DEFINE_STRING_GETTER(get_gateway, host.gateway)
DEFINE_STRING_GETTER(get_hostname, host.hostname)

DEFINE_PATH_GETTER(get_root_path, PATH_ROOT)
DEFINE_PATH_GETTER(get_active_connection_path, PATH_ACTIVE_CONNECTION)
DEFINE_PATH_GETTER(get_connection_path, PATH_CONNECTION)
DEFINE_PATH_GETTER(get_ip4_config_path, PATH_IP4_CONFIG)

DEFINE_SINGLE_PATH_LIST_GETTER(get_device_list, PATH_DEVICE)
DEFINE_SINGLE_PATH_LIST_GETTER(get_active_connection_list, PATH_ACTIVE_CONNECTION)
DEFINE_SINGLE_PATH_LIST_GETTER(get_connection_list, PATH_CONNECTION)

DEFINE_EMPTY_ARRAY_GETTER(get_empty_path_list, "o")
DEFINE_EMPTY_ARRAY_GETTER(get_empty_uint_list, "u")
DEFINE_EMPTY_ARRAY_GETTER(get_empty_string_list, "s")
DEFINE_EMPTY_ARRAY_GETTER(get_empty_dict, "{sv}")
DEFINE_EMPTY_ARRAY_GETTER(get_empty_dict_list, "a{sv}")

static int get_zero_int(GETTER_PARAMS) {
    int32_t number = 0;
    return sd_bus_message_append_basic(reply, SD_BUS_TYPE_INT32, &number);
}

static int get_zero_uint64(GETTER_PARAMS) {
    uint64_t number = 0;
    return sd_bus_message_append_basic(reply, SD_BUS_TYPE_UINT64, &number);
}

static int get_state_reason(GETTER_PARAMS) {
    return sd_bus_message_append(reply, "(uu)", 100u, 0u);
}

static int append_address_entry(sd_bus_message *reply, const char *address, bool include_prefix) {
    int result = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "{sv}");
    if (result < 0)
        return result;

    result = sd_bus_message_append(reply, "{sv}", "address", "s", address);
    if (result < 0)
        return result;

    if (include_prefix) {
        result = sd_bus_message_append(reply, "{sv}", "prefix", "u", host.prefix);
        if (result < 0)
            return result;
    }

    return sd_bus_message_close_container(reply);
}

static int get_address_data(GETTER_PARAMS) {
    int result = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "a{sv}");
    if (result < 0)
        return result;

    result = append_address_entry(reply, host.address, true);
    if (result < 0)
        return result;

    return sd_bus_message_close_container(reply);
}

static int get_nameserver_data(GETTER_PARAMS) {
    int result = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "a{sv}");
    if (result < 0)
        return result;

    for (size_t index = 0; index < host.nameserver_count; index++) {
        result = append_address_entry(reply, host.nameservers[index], false);
        if (result < 0)
            return result;
    }

    return sd_bus_message_close_container(reply);
}

static int reply_with_device_list(METHOD_PARAMS) {
    return sd_bus_reply_method_return(message, "ao", 1, PATH_DEVICE);
}

static int reply_with_connection_list(METHOD_PARAMS) {
    return sd_bus_reply_method_return(message, "ao", 1, PATH_CONNECTION);
}

static int reply_with_empty_permissions(METHOD_PARAMS) {
    return sd_bus_reply_method_return(message, "a{ss}", 0);
}

static int reply_with_connectivity_full(METHOD_PARAMS) {
    return sd_bus_reply_method_return(message, "u", 4u);
}

static int reply_with_state_connected(METHOD_PARAMS) {
    return sd_bus_reply_method_return(message, "u", 70u);
}

static int reply_with_empty_secrets(METHOD_PARAMS) {
    return sd_bus_reply_method_return(message, "a{sa{sv}}", 0);
}

static int reply_with_connection_by_uuid(sd_bus_message *message, void *userdata __attribute__((unused)), sd_bus_error *error) {
    const char *requested_uuid = NULL;
    int result = sd_bus_message_read(message, "s", &requested_uuid);
    if (result < 0)
        return result;

    if (strcmp(requested_uuid, CONNECTION_UUID) != 0)
        return sd_bus_error_set(error, ERROR_INVALID_CONNECTION, "No connection with that UUID");

    return sd_bus_reply_method_return(message, "o", PATH_CONNECTION);
}

static int begin_settings_section(sd_bus_message *reply, const char *section_name) {
    int result = sd_bus_message_open_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}");
    if (result < 0)
        return result;

    result = sd_bus_message_append_basic(reply, SD_BUS_TYPE_STRING, section_name);
    if (result < 0)
        return result;

    return sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "{sv}");
}

static int end_settings_section(sd_bus_message *reply) {
    int result = sd_bus_message_close_container(reply);
    if (result < 0)
        return result;
    return sd_bus_message_close_container(reply);
}

static int append_string_setting(sd_bus_message *reply, const char *key, const char *value) {
    return sd_bus_message_append(reply, "{sv}", key, "s", value);
}

static int append_connection_section(sd_bus_message *reply) {
    int result = begin_settings_section(reply, "connection");
    if (result < 0)
        return result;

    const char *keys[] = { "id", "uuid", "type", "interface-name" };
    const char *values[] = { CONNECTION_ID, CONNECTION_UUID, CONNECTION_TYPE, host.interface_name };
    for (size_t index = 0; index < sizeof(keys) / sizeof(keys[0]); index++) {
        result = append_string_setting(reply, keys[index], values[index]);
        if (result < 0)
            return result;
    }

    return end_settings_section(reply);
}

static int append_method_section(sd_bus_message *reply, const char *section_name, const char *method) {
    int result = begin_settings_section(reply, section_name);
    if (result < 0)
        return result;

    result = append_string_setting(reply, "method", method);
    if (result < 0)
        return result;

    return end_settings_section(reply);
}

static int append_empty_section(sd_bus_message *reply, const char *section_name) {
    int result = begin_settings_section(reply, section_name);
    if (result < 0)
        return result;
    return end_settings_section(reply);
}

static int reply_with_settings(METHOD_PARAMS) {
    sd_bus_message *reply = NULL;
    int result = sd_bus_message_new_method_return(message, &reply);
    if (result < 0)
        return result;

    result = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "{sa{sv}}");
    if (result >= 0)
        result = append_connection_section(reply);
    if (result >= 0)
        result = append_empty_section(reply, CONNECTION_TYPE);
    if (result >= 0)
        result = append_method_section(reply, "ipv4", "auto");
    if (result >= 0)
        result = append_method_section(reply, "ipv6", "ignore");
    if (result >= 0)
        result = sd_bus_message_close_container(reply);
    if (result >= 0)
        result = sd_bus_send(NULL, reply, NULL);

    sd_bus_message_unref(reply);
    return result;
}

static const sd_bus_vtable network_manager_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Devices", "ao", get_device_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("AllDevices", "ao", get_device_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Checkpoints", "ao", get_empty_path_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("NetworkingEnabled", "b", get_true, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("WirelessEnabled", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("WirelessHardwareEnabled", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("WwanEnabled", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("WwanHardwareEnabled", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("ActiveConnections", "ao", get_active_connection_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("PrimaryConnection", "o", get_active_connection_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("PrimaryConnectionType", "s", get_ethernet_type, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Metered", "u", get_u32_4, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("ActivatingConnection", "o", get_root_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Startup", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Version", "s", get_nm_version, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Capabilities", "au", get_empty_uint_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("State", "u", get_u32_70, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Connectivity", "u", get_u32_4, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("ConnectivityCheckAvailable", "b", get_true, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("ConnectivityCheckEnabled", "b", get_true, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("ConnectivityCheckUri", "s", get_empty_string, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("GlobalDnsConfiguration", "a{sv}", get_empty_dict, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("RadioFlags", "u", get_u32_0, 0, CONST_PROPERTY),
    SD_BUS_METHOD("GetDevices", "", "ao", reply_with_device_list, 0),
    SD_BUS_METHOD("GetAllDevices", "", "ao", reply_with_device_list, 0),
    SD_BUS_METHOD("GetPermissions", "", "a{ss}", reply_with_empty_permissions, 0),
    SD_BUS_METHOD("CheckConnectivity", "", "u", reply_with_connectivity_full, 0),
    SD_BUS_METHOD("state", "", "u", reply_with_state_connected, 0),
    SD_BUS_SIGNAL("StateChanged", "u", 0),
    SD_BUS_SIGNAL("DeviceAdded", "o", 0),
    SD_BUS_SIGNAL("DeviceRemoved", "o", 0),
    SD_BUS_SIGNAL("CheckPermissions", "", 0),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable device_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Udi", "s", get_udi, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Path", "s", get_empty_string, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Interface", "s", get_interface_name, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("IpInterface", "s", get_interface_name, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Driver", "s", get_driver_name, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("DriverVersion", "s", get_empty_string, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("FirmwareVersion", "s", get_empty_string, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Capabilities", "u", get_u32_3, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Ip4Address", "u", get_u32_0, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("State", "u", get_u32_100, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("StateReason", "(uu)", get_state_reason, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("ActiveConnection", "o", get_active_connection_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Ip4Config", "o", get_ip4_config_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Dhcp4Config", "o", get_root_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Ip6Config", "o", get_root_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Dhcp6Config", "o", get_root_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Managed", "b", get_true, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Autoconnect", "b", get_true, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("FirmwareMissing", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("NmPluginMissing", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("DeviceType", "u", get_u32_1, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("AvailableConnections", "ao", get_connection_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("PhysicalPortId", "s", get_empty_string, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Mtu", "u", get_u32_1500, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Metered", "u", get_u32_4, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("LldpNeighbors", "aa{sv}", get_empty_dict_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Real", "b", get_true, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Ip4Connectivity", "u", get_u32_4, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Ip6Connectivity", "u", get_u32_1, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("InterfaceFlags", "u", get_u32_interface_flags, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("HwAddress", "s", get_mac, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Ports", "ao", get_empty_path_list, 0, CONST_PROPERTY),
    SD_BUS_SIGNAL("StateChanged", "uuu", 0),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable device_wired_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("HwAddress", "s", get_mac, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("PermHwAddress", "s", get_mac, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Speed", "u", get_u32_1000, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("S390Subchannels", "as", get_empty_string_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Carrier", "b", get_true, 0, CONST_PROPERTY),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable device_statistics_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("RefreshRateMs", "u", get_u32_0, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("TxBytes", "t", get_zero_uint64, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("RxBytes", "t", get_zero_uint64, 0, CONST_PROPERTY),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable active_connection_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Connection", "o", get_connection_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("SpecificObject", "o", get_root_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Id", "s", get_connection_id, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Uuid", "s", get_connection_uuid, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Type", "s", get_ethernet_type, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Devices", "ao", get_device_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("State", "u", get_u32_2, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("StateFlags", "u", get_u32_0, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Default", "b", get_true, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Ip4Config", "o", get_ip4_config_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Dhcp4Config", "o", get_root_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Default6", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Ip6Config", "o", get_root_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Dhcp6Config", "o", get_root_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Vpn", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Master", "o", get_root_path, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Controller", "o", get_root_path, 0, CONST_PROPERTY),
    SD_BUS_SIGNAL("StateChanged", "uu", 0),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable settings_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Connections", "ao", get_connection_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Hostname", "s", get_hostname, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("CanModify", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_METHOD("ListConnections", "", "ao", reply_with_connection_list, 0),
    SD_BUS_METHOD("GetConnectionByUuid", "s", "o", reply_with_connection_by_uuid, 0),
    SD_BUS_SIGNAL("NewConnection", "o", 0),
    SD_BUS_SIGNAL("ConnectionRemoved", "o", 0),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable settings_connection_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Unsaved", "b", get_false, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Flags", "u", get_u32_0, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Filename", "s", get_empty_string, 0, CONST_PROPERTY),
    SD_BUS_METHOD("GetSettings", "", "a{sa{sv}}", reply_with_settings, 0),
    SD_BUS_METHOD("GetSecrets", "s", "a{sa{sv}}", reply_with_empty_secrets, 0),
    SD_BUS_SIGNAL("Updated", "", 0),
    SD_BUS_SIGNAL("Removed", "", 0),
    SD_BUS_VTABLE_END
};

static const sd_bus_vtable ip4_config_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("AddressData", "aa{sv}", get_address_data, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Gateway", "s", get_gateway, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("RouteData", "aa{sv}", get_empty_dict_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("NameserverData", "aa{sv}", get_nameserver_data, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Domains", "as", get_empty_string_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("Searches", "as", get_empty_string_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("DnsOptions", "as", get_empty_string_list, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("DnsPriority", "i", get_zero_int, 0, CONST_PROPERTY),
    SD_BUS_PROPERTY("WinsServerData", "as", get_empty_string_list, 0, CONST_PROPERTY),
    SD_BUS_VTABLE_END
};

static void register_object(sd_bus *bus, const char *object_path, const char *interface_name,
                            const sd_bus_vtable *vtable) {
    int result = sd_bus_add_object_vtable(bus, NULL, object_path, interface_name, vtable, NULL);
    if (result < 0) {
        logmsg("registering %s on %s failed: %s", interface_name, object_path, strerror(-result));
        exit(EXIT_FAILURE);
    }
}

void networkmanager_register(sd_bus *bus) {
    discover_host();

    register_object(bus, PATH_NETWORK_MANAGER, "org.freedesktop.NetworkManager", network_manager_vtable);
    register_object(bus, PATH_DEVICE, "org.freedesktop.NetworkManager.Device", device_vtable);
    register_object(bus, PATH_DEVICE, "org.freedesktop.NetworkManager.Device.Wired", device_wired_vtable);
    register_object(bus, PATH_DEVICE, "org.freedesktop.NetworkManager.Device.Statistics", device_statistics_vtable);
    register_object(bus, PATH_ACTIVE_CONNECTION, "org.freedesktop.NetworkManager.Connection.Active", active_connection_vtable);
    register_object(bus, PATH_SETTINGS, "org.freedesktop.NetworkManager.Settings", settings_vtable);
    register_object(bus, PATH_CONNECTION, "org.freedesktop.NetworkManager.Settings.Connection", settings_connection_vtable);
    register_object(bus, PATH_IP4_CONFIG, "org.freedesktop.NetworkManager.IP4Config", ip4_config_vtable);
}
