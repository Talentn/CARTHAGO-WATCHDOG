// Command attest-spike is the Phase 0 risk-spike-1 verifier: a local HTTP service that
// enrolls a client's TPM attestation key and verifies quotes and Windows boot logs.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"sentinel/backend/internal/attest"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8740", "listen address")
	fetchEK := flag.Bool("fetch-ek", true, "fetch EK certificates and AIA issuers from the TPM manufacturer when not in NV")
	outDir := flag.String("out", "attest-reports", "directory for verification reports")
	once := flag.Bool("once", false, "exit after the first attestation report")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		slog.Error("create out dir", "err", err)
		os.Exit(1)
	}
	v := attest.NewVerifier(*fetchEK)
	done := make(chan *attest.Report, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", handle(func(req attest.EnrollRequest) (any, error) {
		var tpm struct {
			Manufacturer string `json:"manufacturer"`
		}
		_ = json.Unmarshal(req.TPM, &tpm)
		resp, err := v.Enroll(req, tpm.Manufacturer)
		if err == nil {
			slog.Info("enrolled", "id", resp.EnrollmentID, "manufacturer", tpm.Manufacturer)
		}
		return resp, err
	}))
	mux.HandleFunc("POST /v1/activate", handle(func(req attest.ActivateRequest) (any, error) {
		resp, err := v.Activate(req)
		if err == nil {
			slog.Info("activated", "id", req.EnrollmentID)
		}
		return resp, err
	}))
	mux.HandleFunc("POST /v1/attest", handle(func(req attest.AttestRequest) (any, error) {
		rep, err := v.Attest(req)
		if err != nil {
			return nil, err
		}
		name := filepath.Join(*outDir, fmt.Sprintf("report-%s-%s.json", time.Now().UTC().Format("20060102T150405Z"), rep.EnrollmentID))
		if b, err := json.MarshalIndent(rep, "", "  "); err == nil {
			_ = os.WriteFile(name, b, 0o644)
		}
		slog.Info("attested", "id", rep.EnrollmentID, "verdict", rep.Verdict, "ranked", rep.Policy.Ranked, "report", name)
		select {
		case done <- rep:
		default:
		}
		return rep, nil
	}))

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		slog.Info("attest-spike verifier listening", "addr", *listen, "fetch_ek", *fetchEK)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listen", "err", err)
			os.Exit(1)
		}
	}()

	for rep := range done {
		if *once {
			time.Sleep(200 * time.Millisecond)
			_ = srv.Close()
			if rep.Verdict != "pass" {
				os.Exit(2)
			}
			return
		}
	}
}

func handle[Req any](fn func(Req) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req Req
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decode: " + err.Error()})
			return
		}
		resp, err := fn(req)
		if err != nil {
			status := http.StatusInternalServerError
			var ce attest.ClientError
			if errors.As(err, &ce) {
				status = http.StatusBadRequest
			}
			slog.Warn("request failed", "path", r.URL.Path, "err", err)
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
