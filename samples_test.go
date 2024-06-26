//go:build samples

package attestation

import (
	"crypto/x509"
	"io"
	"net/http"
	"testing"
)

var urls = []string{
	// https://github.com/GrapheneOS/Auditor/tree/main/samples
	"https://github.com/GrapheneOS/Auditor/raw/main/samples/3/0_cert-0.der.x509",
	"https://github.com/GrapheneOS/Auditor/raw/main/samples/3/1_strongbox-0_cert-0.der.x509",
	"https://github.com/GrapheneOS/Auditor/raw/main/samples/4/0_cert-0.der.x509",
	"https://github.com/GrapheneOS/Auditor/raw/main/samples/4/1_cert-0.der.x509",
	// https://github.com/GrapheneOS-Archive/AttestationSamples
	// "https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/ALP-L29/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/AUM-L29/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Aquaris%20X2%20Pro/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/BBF100-1/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/BBF100-6/cert-0.der.x509",
	// "https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/BKL-L04/cert-0.der.x509",
	// "https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/BKL-L09/cert-0.der.x509",
	// "https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/CLT-L29/cert-0.der.x509",
	// "https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/COL-L29/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/CPH1831/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/CPH1903/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/CPH1909/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/DUB-LX3/cert-0.der.x509",
	// "https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/EML-L09/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/EXODUS%201/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/G8341/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/G8342/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/G8441/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/GM1913/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/H3113/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/H3123/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/H4113/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/H8216/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/H8314/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/H8324/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/HTC%202Q55100/cert-0.der.x509",
	// "https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/JKM-LX3/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/LG-Q710AL/cert-0.der.x509",
	// "https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/LLD-L31/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/LM-Q720/cert-0.der.x509",
	// "https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/LYA-L29/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/MI%209/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Mi%20A2%20Lite/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Mi%20A2/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Nokia%203.1/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Nokia%206.1%20Plus/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Nokia%206.1/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Nokia%207%20plus/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Nokia%207.1/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/ONEPLUS%20A6003/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/ONEPLUS%20A6013/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/POCOPHONE%20F1/cert-0.der.x509",
	// "https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/POT-LX3/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Pixel%202%20XL/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Pixel%202/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Pixel%203%20XL/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Pixel%203/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Pixel%203a%20XL/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Pixel%203a/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Pixel%204%20XL/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/Pixel%204/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/REVVL%202/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/RMX1941/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-A705FN/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-G9600/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-G960F/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-G960U/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-G960U1/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-G960W/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-G965F/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-G965U/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-G965U1/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-G965W/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-G970F/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-G975F/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-J260A/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-J260F/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-J260T1/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-J337A/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-J337AZ/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-J337T/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-J720F/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-M205F/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-N960F/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-N960U/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-N970F/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-N970U/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-N975U/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-S367VL/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-T510/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SM-T835/cert-0.der.x509",
	// "https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/SNE-LX1/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/moto%20g(7)/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/motorola%20one%20vision/cert-0.der.x509",
	"https://github.com/GrapheneOS-Archive/AttestationSamples/raw/main/vivo%201807/cert-0.der.x509",
}

func TestSamples(t *testing.T) {
	for _, url := range urls {
		t.Run(url, func(t *testing.T) {
			resp, err := http.Get(url)
			if err != nil {
				t.Errorf("failed to download certificate, %v", err)
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("failed to read body, %v", err)
				return
			}

			cert, err := x509.ParseCertificate(body)
			if err != nil {
				t.Errorf("failed to parse certificate, %v", err)
				return
			}

			ext := GetKeyExtension(cert)
			if ext == nil {
				t.Error("failed to get extension")
				return
			}

			_, err = ParseExtension(ext.Value)
			if err != nil {
				t.Errorf("failed to parse extension, %v", err)
				return
			}
		})
	}
}
