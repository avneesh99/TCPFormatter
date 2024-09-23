# TCPFormatter

This CLI tool allows developers to view and analyze TCP dump files in a structured, prettified manner. It helps in debugging HTTP requests and responses captured in PCAP files by presenting them in a readable format. Super useful if you are debugging on an EC2 instance and don't want to install wireshark.

## Features
**Prettified Output:** Extracts HTTP requests and responses from TCP streams and formats them into readable output, including headers and body content.

**Request-Response Pairing:** Automatically matches requests with their corresponding responses, ensuring that both are displayed together for easy debugging.

**Content Decoding:** Supports automatic decompression of HTTP responses with gzip or deflate encoding, so you can directly view the content of compressed responses.

**Stream Reassembly:** Reassembles TCP streams from fragmented packets, ensuring complete request and response bodies are reconstructed even when spread across multiple packets.

**Buffered Stream Handling:** Efficiently handles large amounts of data using buffer-based reassembly, ensuring that incomplete streams do not cause crashes.

**Debug Mode:** Enable a verbose debug mode with the --debug flag to print detailed logs for troubleshooting purposes.

**File Output:** Saves the prettified output of HTTP exchanges into a file (output.txt) for later reference and analysis.

## Usage
```
git clone https://github.com/avneesh99/TCPFormatter
go mod tidy
go build -o TCPFormatter
./TCPFormatter --input <path-to-pcap-file> [--debug]
```
- --input: Path to the input PCAP file.
- --debug: (Optional) Enable debug mode to get detailed error messages and processing information.

## Output
The tool generates an output.txt file in the current directory, containing the parsed and formatted HTTP interactions. Each interaction includes:

- Request details (method, URL, protocol version)
- Request headers
- Request body (if any)
- Response details (protocol version, status code, status message)
- Response headers
- Response body

## Dependencies
- **gopacket:** A Go library for packet processing.
- **pcap:** Used to capture and process network traffic.