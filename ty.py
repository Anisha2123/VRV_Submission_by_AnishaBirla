import re
from collections import defaultdict
import csv

def parse_log_file(file_path):
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    endpoint_pattern = re.compile(r'"[A-Z]+\s(\/[\w\/\-\.]*)')
    failed_login_pattern = re.compile(r'401|Invalid credentials')

    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as log_file:
        for line in log_file:
            ip_match = ip_pattern.search(line)
            endpoint_match = endpoint_pattern.search(line)
            failed_login_match = failed_login_pattern.search(line)

            if ip_match:
                ip = ip_match.group()
                ip_requests[ip] += 1

            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            if failed_login_match and ip_match:
                ip = ip_match.group()
                failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def write_to_csv(ip_requests, endpoint, endpoint_count, failed_logins, output_file="log_analysis_results.csv"):
    with open(output_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)

        # Write Requests per IP
        csvwriter.writerow(["Requests per IP"])
        csvwriter.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            csvwriter.writerow([ip, count])

        # Write Most Accessed Endpoint
        csvwriter.writerow([])
        csvwriter.writerow(["Most Accessed Endpoint"])
        csvwriter.writerow(["Endpoint", "Access Count"])
        csvwriter.writerow([endpoint, endpoint_count])

        # Write Suspicious Activity
        csvwriter.writerow([])
        csvwriter.writerow(["Suspicious Activity"])
        csvwriter.writerow(["IP Address", "Failed Login Count"])
        for ip, count in sorted(failed_logins.items(), key=lambda x: x[1], reverse=True):
            csvwriter.writerow([ip, count])

def main(log_file_path):
    ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file_path)

    # Most accessed endpoint
    most_accessed_endpoint = max(endpoint_requests, key=endpoint_requests.get)
    most_accessed_count = endpoint_requests[most_accessed_endpoint]

    # Suspicious activity threshold
    suspicious_activity_threshold = 10
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > suspicious_activity_threshold}

    # Display results
    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {most_accessed_count} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20}{count}")

    # Save to CSV
    write_to_csv(ip_requests, most_accessed_endpoint, most_accessed_count, suspicious_ips)

if __name__ == "__main__":
    log_file_path = "sample.log"  # Replace with your log file path
    main(log_file_path)
