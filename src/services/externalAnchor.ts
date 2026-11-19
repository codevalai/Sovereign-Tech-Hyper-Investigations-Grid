export {
  RFC3161_TSA_ENDPOINTS,
  RFC3161_TSA_TIMEOUT_MS,
  anchorMerkleRootExternally,
  buildRfc3161StatusDiagnosticJson,
  buildRfc3161TimeStampReqDer,
  hashExternalAnchorReceipt,
  submitRfc3161TsaAnchor,
  type ExternalAnchorReceipt,
  type Rfc3161AttemptDiagnostic,
  type Rfc3161TsaAnchorResult,
} from '../crypto/externalAnchor.ts';
