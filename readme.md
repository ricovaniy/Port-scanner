css
Copy code
# Port Scanner

This command-line utility provides a way to scan ports on a target IP address. It can be used to identify open ports on a remote server.

## Usage

To run the port scanner, follow the steps below:

1. Install the required dependencies by running the command: `pip install -r requirements.txt`
2. Run the command below, replacing the necessary arguments: `python scanner.py <target> <ports> [--timeout <timeout>] [-j, --num-threads <threads_num>] [-v, --verbose] [-g, --guess]`
## Arguments

The utility accepts the following arguments:

- `target`: The target IP address to scan. This argument is required.

- `ports`: The port(s) to scan. You can enter a single port number or multiple port numbers separated by spaces. This argument is required.

- `--timeout <timeout>`: The timeout for the response in seconds. The default value is 4 seconds.

- `-j, --num-threads <threads_num>`: The number of threads to use for scanning. The default value is 50.

- `-v, --verbose`: Enable verbose mode, which provides more detailed output. This argument is optional.

- `-g, --guess`: Enable the guessing of protocols for open ports. This argument is optional.

## Examples

Here are some example commands:

- Scan port 80 and port 443 of the target IP address 192.168.0.1: `python scanner.py 192.168.0.1 80 443`
- Scan port 22, 80, and 443 of the target IP address 10.0.0.1 with a timeout of 2 seconds and verbose mode enabled: `python scanner.py 10.0.0.1 22 80 443 --timeout 2 -v`

Please note that the utility requires appropriate permissions to perform port scanning on a remote server.





