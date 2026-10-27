package wire

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// RecoveryRequestDomain separates the signing bytes of a RecoveryRequest
// from every other signed format (03-06b): a request to import the
// revocations a signer restore lost, which keyroster revoke recover
// prepares offline and keyroster-signer recover-revocations applies under
// the state lock.
const RecoveryRequestDomain = "keyroster/revoke-recovery/v1"

// RecoverySSHSIGNamespace is the SSHSIG namespace of the admin-sshsig/v1
// evidence on a RecoveryRequest. It equals RecoveryRequestDomain (the
// convention of RevokeRequestDomain), so no revocation or issuance approval
// can authorize a recovery and the reverse.
const RecoverySSHSIGNamespace = RecoveryRequestDomain

// Size bounds of a RecoveryRequest.
const (
	// MaxRecoveryRequest bounds the signing bytes (and the request a
	// revocation_recovery leaf logs): a request above it is refused, never
	// truncated.
	MaxRecoveryRequest = 9 << 20
	// MaxRecoveryImports bounds the imported KRL documents.
	MaxRecoveryImports = 4
	// MaxRecoveryKRL bounds one imported KRL: krl.MaxKRL (a test in
	// internal/tlog, which imports both, asserts the equality).
	MaxRecoveryKRL = MaxKRLBytes
	// MaxRecoveryCertificates bounds the carried certificates: the
	// largest count the uint16 count field holds. MaxRecoveryRequest binds
	// first, since even the smallest certificate takes more than
	// MaxRecoveryRequest / MaxRecoveryCertificates bytes (PR #69 review,
	// D-R2; a test asserts it).
	MaxRecoveryCertificates = 1<<16 - 1
	// MaxRecoveryCert bounds one carried certificate: tlog.MaxCert (the
	// same test asserts it).
	MaxRecoveryCert = 64 << 10
	// MaxRecoveryFile bounds the file form (Marshal): the signing bytes
	// plus the largest evidence list.
	MaxRecoveryFile = MaxRecoveryRequest + 2 + MaxEvidence*(2+MaxEvidenceType+2+MaxEvidenceBlob)
)

// RecoveryImport is one imported KRL version: the KRL bytes, the canonical
// manifest and the ops key's armored SSHSIG over it, as keyroster-server
// served them (serverclient.KRLDocument) or as a saved export's last
// krl_publish entry re-derives them.
type RecoveryImport struct {
	KRL      []byte
	Manifest []byte
	Sig      []byte
}

// RecoveredCertificate is one certificate a restore lost, taken from the
// verified leaf bytes of the saved export (SSH wire format), and whether
// the recovery revokes it by serial.
type RecoveredCertificate struct {
	Cert   []byte
	Revoke bool
}

// RecoveryRequest asks the signer to import the revocations a restore
// lost (03-06b). It names the installation it is for and the restored
// log it applies to (its size and root), so it applies to exactly that
// state once. Imports are 0 to MaxRecoveryImports ops-signed KRL versions
// with distinct manifests; Certificates are 0 to MaxRecoveryCertificates
// lost certificates, sorted by serial with no serial twice. CreatedAt is
// the client's clock in Unix seconds. Evidence (admin-sshsig/v1 by one
// policy admin, over SigningBytes under RecoverySSHSIGNamespace) is not
// part of the signing bytes.
type RecoveryRequest struct {
	InstallationID string
	RequestID      [16]byte
	CreatedAt      uint64
	RestoredSize   uint64
	RestoredRoot   [32]byte
	Imports        []RecoveryImport
	Certificates   []RecoveredCertificate
	Evidence       []Evidence
}

// Validate checks the request's limits: an installation ID of the trust
// bundle form, at most MaxRecoveryImports imports, each with a KRL of 1 to
// MaxRecoveryKRL bytes and a manifest and signature within the KRL
// manifest caps, no two with the same manifest, at most
// MaxRecoveryCertificates certificates of 1 to MaxRecoveryCert bytes, each
// an SSH certificate, sorted by serial with no serial twice, and the
// evidence limits. It does not verify any signature.
func (r *RecoveryRequest) Validate() error {
	if !trust.IsInstallationID(r.InstallationID) {
		return fmt.Errorf("%w: the installation ID is not 32 lowercase hex digits", ErrMalformed)
	}
	if len(r.Imports) > MaxRecoveryImports {
		return fmt.Errorf("%w: a recovery imports at most %d KRL versions", ErrMalformed, MaxRecoveryImports)
	}
	for i, im := range r.Imports {
		switch {
		case len(im.KRL) == 0 || len(im.KRL) > MaxRecoveryKRL:
			return fmt.Errorf("%w: import %d: a KRL of 1 to %d bytes", ErrMalformed, i, MaxRecoveryKRL)
		case len(im.Manifest) == 0 || len(im.Manifest) > maxKRLManifest:
			return fmt.Errorf("%w: import %d: manifest size", ErrMalformed, i)
		case len(im.Sig) == 0 || len(im.Sig) > maxKRLManifestSig:
			return fmt.Errorf("%w: import %d: signature size", ErrMalformed, i)
		}
		for _, prev := range r.Imports[:i] {
			if bytes.Equal(prev.Manifest, im.Manifest) {
				return fmt.Errorf("%w: import %d repeats the manifest of an earlier import", ErrMalformed, i)
			}
		}
	}
	if len(r.Certificates) > MaxRecoveryCertificates {
		return fmt.Errorf("%w: a recovery carries at most %d certificates", ErrMalformed, MaxRecoveryCertificates)
	}
	var prev uint64
	for i, c := range r.Certificates {
		if len(c.Cert) == 0 || len(c.Cert) > MaxRecoveryCert {
			return fmt.Errorf("%w: certificate %d: 1 to %d bytes", ErrMalformed, i, MaxRecoveryCert)
		}
		pub, err := ssh.ParsePublicKey(c.Cert)
		if err != nil {
			return fmt.Errorf("%w: certificate %d does not parse", ErrMalformed, i)
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			return fmt.Errorf("%w: certificate %d is a plain key", ErrMalformed, i)
		}
		if i > 0 && cert.Serial <= prev {
			return fmt.Errorf("%w: the certificates must be sorted by serial with no serial twice", ErrMalformed)
		}
		prev = cert.Serial
	}
	if len(r.Evidence) > MaxEvidence {
		return fmt.Errorf("%w: too many evidence items", ErrMalformed)
	}
	for _, e := range r.Evidence {
		if len(e.Type) == 0 || len(e.Type) > MaxEvidenceType || len(e.Blob) > MaxEvidenceBlob {
			return fmt.Errorf("%w: evidence size", ErrMalformed)
		}
	}
	return nil
}

// addFields appends every field except Evidence: the installation ID, the
// request ID, CreatedAt, the restored size and root, the imports (a uint8
// count, then per import the KRL with a uint32 length, the manifest and
// the signature with uint16 lengths) and the certificates (a uint16 count,
// then per certificate the certificate with a uint24 length and one byte,
// 1 to revoke it, 0 to keep it).
func (r *RecoveryRequest) addFields(b *cryptobyte.Builder) {
	addBytes16(b, []byte(r.InstallationID))
	b.AddBytes(r.RequestID[:])
	b.AddUint64(r.CreatedAt)
	b.AddUint64(r.RestoredSize)
	b.AddBytes(r.RestoredRoot[:])
	b.AddUint8(uint8(len(r.Imports))) //nolint:gosec // G115: at most MaxRecoveryImports, checked by Validate
	for _, im := range r.Imports {
		b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(im.KRL) })
		addBytes16(b, im.Manifest)
		addBytes16(b, im.Sig)
	}
	b.AddUint16(uint16(len(r.Certificates))) //nolint:gosec // G115: at most MaxRecoveryCertificates, checked by Validate
	for _, c := range r.Certificates {
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(c.Cert) })
		if c.Revoke {
			b.AddUint8(1)
		} else {
			b.AddUint8(0)
		}
	}
}

// readFields reads what addFields writes into r, without validating it.
func (r *RecoveryRequest) readFields(s *cryptobyte.String) bool {
	var id, reqID, root []byte
	var nImports uint8
	if !readBytes16(s, &id, 64) || !s.ReadBytes(&reqID, len(r.RequestID)) || !s.ReadUint64(&r.CreatedAt) ||
		!s.ReadUint64(&r.RestoredSize) || !s.ReadBytes(&root, len(r.RestoredRoot)) || !s.ReadUint8(&nImports) ||
		int(nImports) > MaxRecoveryImports {
		return false
	}
	r.InstallationID = string(id)
	copy(r.RequestID[:], reqID)
	copy(r.RestoredRoot[:], root)
	for range nImports {
		var (
			n   uint32
			im  RecoveryImport
			raw []byte
		)
		// cryptobyte has no uint32-prefixed reader: read the length, bound
		// it, then the bytes.
		if !s.ReadUint32(&n) || n > MaxRecoveryKRL || !s.ReadBytes(&raw, int(n)) ||
			!readBytes16(s, &im.Manifest, maxKRLManifest) || !readBytes16(s, &im.Sig, maxKRLManifestSig) {
			return false
		}
		im.KRL = append([]byte(nil), raw...)
		r.Imports = append(r.Imports, im)
	}
	var nCerts uint16
	if !s.ReadUint16(&nCerts) || int(nCerts) > MaxRecoveryCertificates {
		return false
	}
	for range nCerts {
		var (
			c      cryptobyte.String
			revoke uint8
		)
		if !s.ReadUint24LengthPrefixed(&c) || len(c) > MaxRecoveryCert || !s.ReadUint8(&revoke) || revoke > 1 {
			return false
		}
		r.Certificates = append(r.Certificates, RecoveredCertificate{Cert: append([]byte(nil), c...), Revoke: revoke == 1})
	}
	return true
}

// SigningBytes returns the domain tag (RecoveryRequestDomain), as raw
// bytes, followed by every field except Evidence. A revocation_recovery
// leaf logs exactly these bytes, and ParseRecoverySigningBytes reads them
// back. It refuses a request that Validate refuses and signing bytes above
// MaxRecoveryRequest.
func (r *RecoveryRequest) SigningBytes() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddBytes([]byte(RecoveryRequestDomain))
	r.addFields(&b)
	out, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(out) > MaxRecoveryRequest {
		return nil, fmt.Errorf("%w: the recovery request takes %d bytes, above %d", ErrMalformed, len(out), MaxRecoveryRequest)
	}
	return out, nil
}

// Marshal encodes the file form: the signing bytes, then the evidence (a
// uint16-length-prefixed list of type and blob, each uint16-length
// prefixed).
func (r *RecoveryRequest) Marshal() ([]byte, error) {
	sb, err := r.SigningBytes()
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddBytes(sb)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, e := range r.Evidence {
			addBytes16(b, []byte(e.Type))
			addBytes16(b, e.Blob)
		}
	})
	return b.Bytes()
}

// ParseRecoveryRequest decodes the file form strictly: at most
// MaxRecoveryFile bytes, the domain tag, every limit of Validate, a
// revoke byte other than 0 or 1 refused, and trailing bytes refused. The
// result's Marshal equals data.
func ParseRecoveryRequest(data []byte) (*RecoveryRequest, error) {
	if len(data) > MaxRecoveryFile {
		return nil, fmt.Errorf("%w: a recovery request of %d bytes, above %d", ErrMalformed, len(data), MaxRecoveryFile)
	}
	rest, ok := bytes.CutPrefix(data, []byte(RecoveryRequestDomain))
	if !ok {
		return nil, fmt.Errorf("%w: not a recovery request (%s)", ErrMalformed, RecoveryRequestDomain)
	}
	s := cryptobyte.String(rest)
	var (
		r        RecoveryRequest
		evidence cryptobyte.String
	)
	if !r.readFields(&s) || !s.ReadUint16LengthPrefixed(&evidence) || !s.Empty() {
		return nil, ErrMalformed
	}
	for !evidence.Empty() {
		if len(r.Evidence) == MaxEvidence {
			return nil, fmt.Errorf("%w: too many evidence items", ErrMalformed)
		}
		var typ, blob []byte
		if !readBytes16(&evidence, &typ, MaxEvidenceType) || !readBytes16(&evidence, &blob, MaxEvidenceBlob) {
			return nil, ErrMalformed
		}
		r.Evidence = append(r.Evidence, Evidence{Type: string(typ), Blob: blob})
	}
	out, err := r.Marshal()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(out, data) {
		return nil, fmt.Errorf("%w: the recovery request does not re-encode identically", ErrMalformed)
	}
	return &r, nil
}

// ParseRecoverySigningBytes decodes the signing bytes of a request, which
// a revocation_recovery leaf logs as its request
// (tlog.RecoveryBody.Request), strictly: at most MaxRecoveryRequest bytes,
// the raw domain tag first, the limits of ParseRecoveryRequest and
// trailing bytes refused. The result carries no evidence, and its
// SigningBytes equal b.
func ParseRecoverySigningBytes(b []byte) (*RecoveryRequest, error) {
	if len(b) > MaxRecoveryRequest {
		return nil, fmt.Errorf("%w: recovery signing bytes of %d bytes, above %d", ErrMalformed, len(b), MaxRecoveryRequest)
	}
	rest, ok := bytes.CutPrefix(b, []byte(RecoveryRequestDomain))
	if !ok {
		return nil, fmt.Errorf("%w: not the signing bytes of a recovery request", ErrMalformed)
	}
	s := cryptobyte.String(rest)
	var r RecoveryRequest
	if !r.readFields(&s) || !s.Empty() {
		return nil, ErrMalformed
	}
	out, err := r.SigningBytes()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(out, b) {
		return nil, fmt.Errorf("%w: the signing bytes do not re-encode identically", ErrMalformed)
	}
	return &r, nil
}
