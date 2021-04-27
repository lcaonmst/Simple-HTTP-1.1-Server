/* Project nr 1 SK
 * Server implementation
 * C++17
 * Kamil Zwierzchowski
 * kz418510
 */

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <experimental/filesystem>
#include <regex>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <ctime>


using std::string;
using std::regex;
using std::regex_match;
namespace fs = std::experimental::filesystem;


#define PROT string("http://")
#define ZERO string("0")
#define COLON string(":")
#define GET string("GET")
#define HEAD string("HEAD")
#define HTTP string("HTTP/1.1")
#define OCTET_STREAM string("application/octet-stream")
#define CLOSE string("close")
#define CONNECTION string("Connection")
#define CONNECTION_DATA string("connection")
#define CONTENT_LENGTH_DATA string("content-length")
#define CONTENT_TYPE string("Content-type")
#define CONTENT_LENGTH string("Content-length")
#define LOCATION string("Location")

#define DOT string(".")
#define COME_BACK_DIR string("..")
#define SPACE string(" ")
#define ASCII_13 '\x0d'
#define ASCII_10 '\x0a'
#define CRLF (string(1, ASCII_13) + string(1, ASCII_10))
#define CONNECTION_LINE (string("Connection: close") + CRLF)
#define CONTENT_TYPE_LINE (CONTENT_TYPE + COLON + SPACE + OCTET_STREAM + CRLF)
#define SERVER_LINE (string("Server: HTTP/1.1 server by lcaonmst.") + CRLF)

#define SUCCESS_INFO string("Successful file read.")
#define WRITE_ERROR_INFO string("Unsuccessful write from socket.")
#define READ_ERROR_INFO string("Unsuccessful read from socket.")
#define EXTERNAL_RESOURCE_INFO string("Targeted file has been moved.")
#define INVALID_PATH_INFO string("Invalid request target.")
#define INVALID_HTTP_INFO string("Invalid HTTP version. Expected: HTTP/1.1.")
#define NO_HEADER_VALUE_INFO string("No header value provided.")
#define EMPTY_HEADER_NAME_INFO string("No header name provided.")
#define MAXIMUM_REQUEST_LENGTH_EXCEEDED_INFO string("Maximum request length exceeded.")
#define TIMEOUT_INFO string("Timeout has been reached.")
#define HEADER_REPETITION_INFO string("Repetition of header.")
#define INVALID_CONNECTION_HEADER_INFO string("Invalid connection value. Expected: close.")
#define INVALID_CONTENT_LENGTH_HEADER_INFO string("Invalid content-length value. Expected: 0.")
#define ATTEMPT_TO_ACCESS_OUTSIDE_INFO string("Attempt to access file outside given directory.")
#define READING_FILE_FAILED_INFO string("Unable to read from file.")
#define FILE_NOT_FOUND_INFO string("File not found.")
#define NOT_SUPPORTED_INFO string("Not supported request method. Supported: GET or HEAD.")

#define SUCCESS_REQUEST_CODE 200
#define EXTERNAL_RESOURCE_CODE 302
#define INVALID_REQUEST_CODE 400
#define UNKNOWN_REQUEST_CODE 404
#define SERVER_ERROR_CODE 500
#define NOT_SUPPORTED_CODE 501

#define METHOD_MODE 0
#define TARGET_MODE 1
#define HTTP_VERSION_MODE 2
#define HEADER_MODE 3
#define BODY_MODE 4

#define UNDEFINED 0
#define GET_METHOD 1
#define HEAD_METHOD 2


#define FILE_CHARS string("a-zA-Z0-9\\.\\-")
#define PATH_CHARS (FILE_CHARS + string("\\/"))
#define PATHNAME string("[") + PATH_CHARS + string("]+")
#define IP_ADDRESS string("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")
#define PORT_NUMBER string("[0-9]{1,5}")
#define TAB string("\t")
#define EXTERNAL_DATA (PATHNAME + TAB + IP_ADDRESS + TAB + PORT_NUMBER)


#define MAX_PORT UINT16_MAX
#define DEFAULT_PORT 8080
#define BUFFER_SIZE 4096
#define QUEUE_LENGTH 5
#define MAX_REQUEST 8192
#define TIMEOUT 45


#define STOP_ON_CHAR(x, y)              \
switch (message_part) {                 \
    case METHOD_MODE:                   \
        getline((x), (y), ' ');         \
        break;                          \
    case TARGET_MODE:                   \
        getline((x), (y), ' ');         \
        break;                          \
    default:                            \
        getline((x), (y), ASCII_10);    \
        break;                          \
}

#define FULL_ERROR_CHECK(x)                                                                         \
switch(message_part) {                                                                              \
    case METHOD_MODE:                                                                               \
        if ((x) == GET) {                                                                           \
            request_data.method = GET_METHOD;                                                       \
        }                                                                                           \
        else if ((x) == HEAD) {                                                                     \
            request_data.method = HEAD_METHOD;                                                      \
        }                                                                                           \
        else {                                                                                      \
            killed = true;                                                                          \
            send_error(msg_sock, NOT_SUPPORTED_CODE, NOT_SUPPORTED_INFO);                           \
        }                                                                                           \
        break;                                                                                      \
    case TARGET_MODE:                                                                               \
        if (!regex_match((x), regex(PATHNAME)) || !correct_path((x))) {                             \
            killed = true;                                                                          \
            send_error(msg_sock, INVALID_REQUEST_CODE, INVALID_PATH_INFO);                          \
        }                                                                                           \
        else {                                                                                      \
            request_data.request_target = (x);                                                      \
        }                                                                                           \
        break;                                                                                      \
    case HTTP_VERSION_MODE:                                                                         \
        if ((x) != HTTP) {                                                                          \
            killed = true;                                                                          \
            send_error(msg_sock, INVALID_REQUEST_CODE, INVALID_HTTP_INFO);                          \
        }                                                                                           \
        break;                                                                                      \
    default:                                                                                        \
        std::size_t semi = (x).find_first_of(':');                                                  \
        if (semi == string::npos) {                                                                 \
            killed = true;                                                                          \
            send_error(msg_sock, INVALID_REQUEST_CODE, NO_HEADER_VALUE_INFO);                       \
        }                                                                                           \
        else {                                                                                      \
            string header_name = (x).substr(0, semi);                                               \
            string header_value = (x).substr(semi + 1);                                             \
            to_lower_case(header_name);                                                             \
            remove_spaces(header_value);                                                            \
            if (header_name.empty()) {                                                              \
                killed = true;                                                                      \
                send_error(msg_sock, INVALID_REQUEST_CODE, EMPTY_HEADER_NAME_INFO);                 \
                break;                                                                              \
            }                                                                                       \
            if (compare_case_insensitive(header_name, CONNECTION)) {                                \
                if (header_value != CLOSE) {                                                        \
                    killed = true;                                                                  \
                    send_error(msg_sock, INVALID_REQUEST_CODE, INVALID_CONNECTION_HEADER_INFO);     \
                    break;                                                                          \
                }                                                                                   \
                if (request_data.headers_data.count(CONNECTION_DATA) > 0) {                         \
                    killed = true;                                                                  \
                    send_error(msg_sock, INVALID_REQUEST_CODE, HEADER_REPETITION_INFO);             \
                    break;                                                                          \
                }                                                                                   \
                request_data.headers_data[header_name] = header_value;                              \
            }                                                                                       \
            if (compare_case_insensitive(header_name, CONTENT_LENGTH)) {                            \
                if (header_value != ZERO) {                                                         \
                    killed = true;                                                                  \
                    send_error(msg_sock, INVALID_REQUEST_CODE, INVALID_CONTENT_LENGTH_HEADER_INFO); \
                    break;                                                                          \
                }                                                                                   \
                if (request_data.headers_data.count(CONTENT_LENGTH_DATA) > 0) {                     \
                    killed = true;                                                                  \
                    send_error(msg_sock, INVALID_REQUEST_CODE, HEADER_REPETITION_INFO);             \
                    break;                                                                          \
                }                                                                                   \
                request_data.headers_data[header_name] = header_value;                              \
            }                                                                                       \
                                                                                                    \
        }                                                                                           \
}

using headers_data_t = std::unordered_map<string, string>;


struct External_resource {
    string ip_address;
    uint16_t port_number = 0;
};

struct Request_data {
    int method = UNDEFINED;
    string request_target;
    headers_data_t headers_data;
};

/* Structure that closes socket whenever exits declaration scope.
 */
struct RAIISock {
    int32_t socket;

    explicit RAIISock(int32_t sock) : socket(sock) {}

    ~RAIISock() {
        close(socket);
    }
};

using external_resource_t = External_resource;
using request_data_t = Request_data;
using external_data_t = std::unordered_map<string, external_resource_t>;


/* Function prints on standard output some data with marked date.
 */
void status(const string &x) {
    time_t raw_time;
    tm *time_info;
    time(&raw_time);
    time_info = localtime(&raw_time);
    string t = asctime(time_info);
    if (!t.empty()) {
        t.pop_back();
    }
    std::cout << string("[STATUS  ") << t << string("]    ") << string(x) << std::endl;
}

/* Function tries to convert string to filesystem::path object.
 * If string represents relative path, then it is converted to absolute path.
 */
fs::path absolute_path(const std::string &data) {
    fs::path path(data);
    if (path.is_relative()) {
        return fs::absolute(path);
    }
    else {
        return path;
    }
}

/* Function tries to save data from file with correlated servers to local structure.
 * First argument is path to file.
 * Second argument is structure where it saves data.
 * Returns true if succeeded, false otherwise.
 */
bool get_correlated_files(const fs::path &path, external_data_t &external) {
    std::ifstream file(path, std::ios::in);
    if (!file.is_open()) {
        return false;
    }
    string line;
    while (getline(file, line)) {
        if (!regex_match(line, regex(EXTERNAL_DATA))) {
            return false;
        }

        std::stringstream s(line);
        string resource, server, port;
        getline(s, resource, '\t');
        getline(s, server, '\t');
        getline(s, port);


        fs::path resource_path(resource);
        uint32_t port_number = stoi(port);
        if (MAX_PORT < port_number) {
            return false;
        }

        if (external.count(resource) == 0) {
            external_resource_t external_resource;
            external_resource.ip_address = server;
            external_resource.port_number = (uint16_t)port_number;
            external[resource] = std::move(external_resource);
        }
    }
    return true;
}

/* Function sends error to client described by arguments.
 * First argument is socket descriptor.
 * Second argument is request error code.
 * Third argument is additional information of error.
 * Fourth argument is location header.
 * Fifth argument is true if function should add connection header, false otherwise.
 * Function returns true if succeeded, false otherwise.
 */
bool send_error(int32_t sock, uint16_t error_code, const string &additional_info, const string &location="", bool force_end = false) {
    string message = HTTP + SPACE + std::to_string(error_code) + SPACE + additional_info + CRLF + location;
    if ((error_code == INVALID_REQUEST_CODE || error_code == SERVER_ERROR_CODE || error_code == NOT_SUPPORTED_CODE) || force_end) {
        message += CONNECTION_LINE;
    }
    message += SERVER_LINE;
    message += CRLF;
    status("Error nr " + std::to_string(error_code) + " occurred. " + additional_info);
    ssize_t snd_len = send(sock, message.c_str(), strlen(message.c_str()), MSG_NOSIGNAL);
    if (snd_len != (int32_t)strlen(message.c_str())) {
        return false;
    }
    return true;
}

/* Function sends respond (or error if incorrect request) to client described by arguments.
 * First argument is socket descriptor.
 * Second argument is structure describing request.
 * Third argument is absolute path on directory with server resources.
 * Fourth argument is structure describing correlated servers.
 * Returns false if connection should be aborted, true otherwise.
 */
bool handle_request(int32_t sock, request_data_t &request_data, fs::path main_dir, external_data_t &external_data) {
    bool to_kill = request_data.headers_data.count(CONNECTION_DATA) == 1;
    if (request_data.request_target.back() == '/') {
        send_error(sock, UNKNOWN_REQUEST_CODE, FILE_NOT_FOUND_INFO, "", to_kill);
        return true;
    }
    int32_t ile = 0;
    std::stringstream s(request_data.request_target);
    string curr_dir;
    bool ok = true;
    while (getline(s, curr_dir, '/')) {
        if (curr_dir == COME_BACK_DIR) {
            ile--;
        }
        else if (!curr_dir.empty() && curr_dir != DOT) {
            ile++;
        }
        if (ile < 0) {
            ok = false;
        }
    }
    if (!ok) {
        send_error(sock, UNKNOWN_REQUEST_CODE, ATTEMPT_TO_ACCESS_OUTSIDE_INFO, "", to_kill);
        return true;
    }
    main_dir /= fs::path(request_data.request_target);
    struct stat result{};
    std::ifstream file(main_dir, std::ios::in | std::ios::binary);
    if (!exists(main_dir) || stat(main_dir.c_str(), &result) != 0 || !file.is_open()) {
        if (external_data.count(request_data.request_target) > 0) {
            external_resource_t *external_resource_ptr = &external_data[request_data.request_target];
            string loc = LOCATION + COLON + SPACE + PROT + external_resource_ptr->ip_address + COLON +
                         std::to_string(external_resource_ptr->port_number) + request_data.request_target + CRLF;
            send_error(sock, EXTERNAL_RESOURCE_CODE, EXTERNAL_RESOURCE_INFO, loc, to_kill);
            return true;
        }
        send_error(sock, UNKNOWN_REQUEST_CODE, FILE_NOT_FOUND_INFO, "", to_kill);
        return true;
    }
    string info = HTTP + SPACE + std::to_string(SUCCESS_REQUEST_CODE) + SPACE + SUCCESS_INFO + CRLF;
    if (to_kill) {
        info += CONNECTION_LINE;
    }
    info += CONTENT_TYPE_LINE;
    info += CONTENT_LENGTH + COLON + SPACE + std::to_string(result.st_size) + CRLF;
    info += SERVER_LINE;
    info += CRLF;
    ssize_t snd_len = write(sock, info.c_str(), info.length());
    if (request_data.method == HEAD_METHOD) {
        status("HEAD request processed successfully.");
        return !to_kill;
    }

    if (snd_len != (int32_t)info.length()) {
        send_error(sock, SERVER_ERROR_CODE, WRITE_ERROR_INFO);
        return false;
    }
    char buffer[BUFFER_SIZE];
    file.read(buffer, BUFFER_SIZE);
    while (file.gcount() > 0) {
        snd_len = send(sock, buffer, file.gcount(), MSG_NOSIGNAL);
        if (snd_len != file.gcount()) {
            send_error(sock, SERVER_ERROR_CODE, WRITE_ERROR_INFO);
            return false;
        }
        file.read(buffer, BUFFER_SIZE);
    }
    status("GET request processed successfully.");
    return !to_kill;
}

/* Function moves to next part of request.
 */
void next_mode(uint8_t &mode) {
    mode++;
    if (mode == BODY_MODE) {
        mode = HEADER_MODE;
    }
}

/* Function removes leading and trailing spaces from string.
 */
void remove_spaces(string &s) {
    size_t start = s.find_first_not_of(SPACE);
    (start == string::npos) ? s.clear() : (void)(s = s.substr(start));
    size_t end = s.find_last_not_of(SPACE);
    (end == string::npos) ? s.clear() : (void)(s = s.substr(0, end + 1));
}

/* Function checks whether path starts with '/' or not.
 */
bool correct_path(const string &path) {
    if (path.empty() || path.front() != '/') {
        return false;
    }
    return true;
}

/* Function converts string to lower cases.
 */
void to_lower_case(string &s) {
    for (char &c : s) {
        c = (char)tolower(c);
    }
}

/* Function compare strings with an accuracy of up to letters capitalize.
 */
bool compare_case_insensitive(const string &s1, const string &s2) {
    if (s1.length() != s2.length()) {
        return false;
    }
    for (uint32_t i = 0; i < s1.length(); i++) {
        if (tolower(s1[i]) != tolower(s2[i])) {
            return false;
        }
    }
    return true;
}

/* Function clears request_data structure for next use.
 */
void request_data_clear(request_data_t &request_data) {
    request_data.method = UNDEFINED;
    request_data.request_target.clear();
    request_data.headers_data.clear();
}

/* Function executes server.
 * First argument is server source path.
 * Second argument is path to file with correlated servers.
 * Third argument (optional) is port number where server should listen.
 */
int main(int argc, char **argv) {
    status("Server starts running.");
    if (argc < 3 || argc > 4) {
        status("Invalid number of arguments. Quiting.");
        return EXIT_FAILURE;
    }

    const fs::path filesystem_path = absolute_path(string(argv[1]));
    if (!fs::is_directory(filesystem_path)) {
        status("Invalid path to resources. Quiting.");
        return EXIT_FAILURE;
    }
    const fs::path correlated_path = absolute_path(string(argv[2]));
    if (!fs::is_regular_file(correlated_path)) {
        status("Invalid path to correlated files. Quiting");
        return EXIT_FAILURE;
    }


    uint16_t port_number = DEFAULT_PORT;
    if (argc == 4) {
        if (!regex_match(argv[3], regex(PORT_NUMBER))) {
            status("Invalid port number. Quiting.");
            return EXIT_FAILURE;
        }
        uint32_t new_port_number = atoi(argv[3]);
        if (MAX_PORT < new_port_number) {
            status("Invalid port number. Quiting");
            return EXIT_FAILURE;
        }
        port_number = (uint16_t)new_port_number;
    }

    external_data_t external_data;
    if (!get_correlated_files(correlated_path, external_data)) {
        status("Correlated files does not match signature. Quiting.");
        return EXIT_FAILURE;
    }


    int32_t sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        status("Unable to create socket. Quiting.");
        return EXIT_FAILURE;
    }
    status("Socket created.");
    RAIISock server_sock(sock);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(port_number);
    if (bind(sock, (sockaddr*)&server_address, sizeof(server_address)) < 0) {
        status("Unable to bind port. Check if port is free. Quiting.");
        return EXIT_FAILURE;
    }
    status("Port bound.");
    if (listen(sock, QUEUE_LENGTH) < 0) {
        status("Unable to start listening on socket. Quiting.");
        return EXIT_FAILURE;
    }
    char buffer[BUFFER_SIZE];
    uint32_t connection_number = 0;

    for (;;) {
        status("Server starts listening.");
        sockaddr_in client_address{};
        socklen_t client_address_len = sizeof(client_address);
        int32_t msg_sock = accept(sock, (sockaddr*)&client_address, &client_address_len);
        status("Connection request.");
        if (msg_sock < 0) {
            status("Connection failed");
            continue;
        }
        connection_number++;
        status("Connection nr " + std::to_string(connection_number) + " accepted.");
        RAIISock client_sock(msg_sock);

        uint8_t message_part = METHOD_MODE;
        string curr_part;
        request_data_t request_data;
        bool killed = false;
        ssize_t len;
        do {
            fd_set set;
            timeval timeout{};
            FD_ZERO(&set);
            FD_SET(msg_sock, &set);
            timeout.tv_sec = TIMEOUT;
            timeout.tv_usec = 0;
            int32_t rv = select(msg_sock + 1, &set, nullptr, nullptr, &timeout);
            if (rv == -1) {
                send_error(msg_sock, SERVER_ERROR_CODE, READ_ERROR_INFO);
                status("Ending connection nr " + std::to_string(connection_number) + DOT);
                break;
            }
            if (rv == 0) {
                send_error(msg_sock, INVALID_REQUEST_CODE, TIMEOUT_INFO);
                status("Ending connection nr " + std::to_string(connection_number) + DOT);
                break;
            }
            len = read(msg_sock, buffer, sizeof(buffer));
            if (len < 0) {
                send_error(msg_sock, SERVER_ERROR_CODE, READ_ERROR_INFO);
                break;
            }
            if (len < (uint32_t)sizeof(buffer)) {
                buffer[len] = '\0';
            }
            std::stringstream s(buffer);
            string new_part;
            STOP_ON_CHAR(s, new_part);
            while (!s.eof()) {
                if ((message_part == HTTP_VERSION_MODE || message_part == HEADER_MODE) && (new_part.empty() || new_part.back() != ASCII_13)) {
                    curr_part += new_part + ASCII_10;
                }
                else {
                    if (message_part == HTTP_VERSION_MODE || message_part == HEADER_MODE) {
                        new_part.pop_back();
                    }
                    curr_part += new_part;
                    if (curr_part.length() == 0 && message_part == HEADER_MODE) {
                        if (!handle_request(msg_sock, request_data, filesystem_path, external_data)) {
                            killed = true;
                        }
                        message_part = METHOD_MODE;
                        request_data_clear(request_data);
                    }
                    else {
                        FULL_ERROR_CHECK(curr_part);
                        next_mode(message_part);
                    }
                    curr_part.clear();
                    new_part.clear();
                    if (killed) {
                        break;
                    }
                }
                STOP_ON_CHAR(s, new_part);
            }
            if (killed) {
                status("Ending connection nr " + std::to_string(connection_number) + DOT);
                break;
            }
            curr_part += new_part;
            if (curr_part.length() > MAX_REQUEST) {
                send_error(msg_sock, UNKNOWN_REQUEST_CODE, MAXIMUM_REQUEST_LENGTH_EXCEEDED_INFO, "", true);
                status("Ending connection nr " + std::to_string(connection_number) + DOT);
                break;
            }
            if (len == 0) {
                status("Ending connection nr " + std::to_string(connection_number) + DOT);
            }
        } while (len > 0);
    }
    return 0;
}
