package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

var (
	inputFile = flag.String("input", "", "Path to the input PCAP file")
	debug     = flag.Bool("debug", false, "Enable debug mode")
)

type key struct {
	net, transport gopacket.Flow
}

func (k key) String() string {
	return fmt.Sprintf("%v:%v", k.net, k.transport)
}

type customStream struct {
	bytes []byte
	bidi  *bidi
	done  bool
}

type bidi struct {
	key               key
	a, b              *customStream
	lastPacketSeen    time.Time
	lastProcessedTime time.Time
}

type myFactory struct {
	bidiMap map[key]*bidi
}

func (f *myFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	s := &customStream{}
	k := key{netFlow, tcpFlow}
	bd := f.bidiMap[k]
	if bd == nil {
		bd = &bidi{a: s, key: k}
		f.bidiMap[key{netFlow.Reverse(), tcpFlow.Reverse()}] = bd
	} else {
		bd.b = s
		delete(f.bidiMap, k)
	}
	s.bidi = bd
	bd.lastProcessedTime = time.Now()
	return s
}

func (s *customStream) Reassembled(rs []tcpassembly.Reassembly) {
	if s.done {
		return
	}
	for _, r := range rs {
		if r.Skip > 0 {
			s.done = true
			return
		}
		s.bytes = append(s.bytes, r.Bytes...)
		if s.bidi.lastPacketSeen.Before(r.Seen) {
			s.bidi.lastPacketSeen = r.Seen
		}
	}
}

func (s *customStream) ReassemblyComplete() {
	s.done = true
	s.bidi.maybeFinish()
}

func tryReadFromBD(bd *bidi) {
	reader := bufio.NewReader(bytes.NewReader(bd.a.bytes))
	var requests []http.Request
	var requestsContent []string

	for {
		req, err := http.ReadRequest(reader)
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			if *debug {
				fmt.Printf("HTTP-request error: %s\n", err)
			}
			return
		}
		body, err := io.ReadAll(req.Body)
		errReq := req.Body.Close()
		if errReq != nil {
			return
		}
		if err != nil {
			if *debug {
				fmt.Printf("Got body err: %s\n", err)
			}
			return
		}

		requests = append(requests, *req)
		requestsContent = append(requestsContent, string(body))
	}

	if len(requests) == 0 {
		return
	}

	reader = bufio.NewReader(bytes.NewReader(bd.b.bytes))
	var responses []http.Response
	var responsesContent []string

	for {
		resp, err := http.ReadResponse(reader, nil)
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}
		encoding := resp.Header["Content-Encoding"]
		var r io.Reader
		r = bytes.NewBuffer(body)
		if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
			r, err = gzip.NewReader(r)
			if err != nil {
				return
			}
		}
		body, err = io.ReadAll(r)
		if _, ok := r.(*gzip.Reader); ok {
			err := r.(*gzip.Reader).Close()
			if err != nil {
				return
			}
		}

		responses = append(responses, *resp)
		responsesContent = append(responsesContent, string(body))
	}

	if len(requests) != len(responses) {
		return
	}

	for i, req := range requests {
		resp := &responses[i]

		reqHeader := make(map[string][]string)
		for name, values := range req.Header {
			reqHeader[name] = values
		}

		respHeader := make(map[string][]string)
		for name, values := range resp.Header {
			respHeader[name] = values
		}

		saveToFile(fmt.Sprintf(
			"[req-resp]:\n%s %s %s\n%s\n%s\n\n\n%s %d %s\n%s\n%s\n\n\n",
			req.Method, req.URL.String(), req.Proto,
			formatHeaders(reqHeader), requestsContent[i],
			resp.Proto, resp.StatusCode, resp.Status,
			formatHeaders(respHeader), responsesContent[i],
		))
	}
}

func formatHeaders(headers map[string][]string) string {
	var sb strings.Builder
	for k, v := range headers {
		for _, val := range v {
			sb.WriteString(fmt.Sprintf("%s: %s\n", k, val))
		}
	}
	return sb.String()
}

func (bd *bidi) maybeFinish() {
	switch {
	case bd.a == nil:
		if *debug {
			log.Printf("[%v] a should always be non-nil, since it's set when bidis are created\n", bd.key)
		}
	case bd.b == nil:
		if *debug {
			log.Printf("[%v] no second stream yet\n", bd.key)
		}
	default:
		tryReadFromBD(bd)
		bd.a.bytes = make([]byte, 0)
		bd.b.bytes = make([]byte, 0)
	}
}

func createAndGetAssembler() *tcpassembly.Assembler {
	streamFactory := &myFactory{bidiMap: make(map[key]*bidi)}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	assembler.MaxBufferedPagesTotal = 100000
	assembler.MaxBufferedPagesPerConnection = 1000
	return assembler
}

func flushAll(assembler *tcpassembly.Assembler) {
	assembler.FlushOlderThan(time.Now().Add(time.Second * -30))
}

func run(handle *pcap.Handle, assembler *tcpassembly.Assembler) {
	if err := handle.SetBPFFilter("tcp"); err != nil {
		log.Fatal(err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			continue
		} else {
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		}
	}

	flushAll(assembler)
}

func saveToFile(data string) {
	f, err := os.OpenFile("output.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		if *debug {
			fmt.Printf("Error opening file: %s\n", err)
		}
		return
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			if *debug {
				fmt.Println("Error closing file", err)
			}
		}
	}(f)

	if _, err := f.WriteString(data + "\n\n"); err != nil {
		if *debug {
			fmt.Printf("Error writing to file: %s\n", err)
		}
	}
}

func main() {
	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Please provide the input PCAP file path using the --input flag.")
		return
	}

	handle, err := pcap.OpenOffline(*inputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	assembler := createAndGetAssembler()
	run(handle, assembler)
}
