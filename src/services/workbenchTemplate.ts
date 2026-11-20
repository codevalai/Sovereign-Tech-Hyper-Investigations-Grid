import type {
  BftCorroborationSummary,
  LiveBusinessIntelligence,
  PropertyGraphEdge,
  PropertyGraphNode,
  TechEntity,
} from '../types/investigation';
import type {
  AdversarialTribunalResult,
  BenfordAnalysisResult,
  ForensicPropertyGraphResult,
  HawkesAnalysisResult,
  StylometricResult,
} from './forensicMathEngine';

export interface DossierFileEntry {
  filename: string;
  description: string;
  content: string;
  type: 'markdown' | 'json' | 'csv' | 'html' | 'text';
}

export function buildShadowSpvGraphJson(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined,
  benford: BenfordAnalysisResult,
  timestampIso: string
): string {
  const sf = liveIntel?.shadowFinance;
  return JSON.stringify(
    {
      target_entity: matchedEntity.name,
      legal_name: matchedEntity.legalName,
      generated_at: timestampIso,
      live_grounded: Boolean(liveIntel),
      spv_and_parent_links: sf?.spvAndParentLinks || [],
      sec_form_d_exempt_offerings: sf?.formDOfferings || [],
      sec_xbrl_gaap_facts_count: sf?.xbrlFacts.length || 0,
      sec_xbrl_gaap_sample: (sf?.xbrlFacts || []).slice(0, 20),
      usaspending_awards: liveIntel?.governmentSubsidiesAndGrants || [],
      federal_register_notices: sf?.federalRegisterDocs || [],
      patent_assignment_leads: sf?.patentSignals || [],
      benford_first_digit_analysis: benford,
    },
    null,
    2
  );
}

export function buildRevolvingDoorCsv(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined
): string {
  const header =
    'Record_Type,Year,Date_Posted,Registrant_Or_Agency,Client_Entity,Lobbyist_Official,Covered_Government_Position,Lobbied_Agencies,Amount_USD,Issue_Areas,Source_URL';
  const rows: string[] = [];

  const sf = liveIntel?.shadowFinance;
  if (sf) {
    for (const lf of sf.lobbyingFilings) {
      const agencies = lf.agencies.join('; ') || 'Federal Legislative/Executive';
      const issues = lf.issues.join('; ') || 'General Corporate';
      if (lf.revolvingDoorOfficials.length > 0) {
        for (const off of lf.revolvingDoorOfficials) {
          rows.push(
            [
              'SENATE_LDA_REVOLVING_DOOR',
              lf.filingYear,
              lf.dtPosted,
              `"${lf.registrantName.replace(/"/g, '""')}"`,
              `"${lf.clientName.replace(/"/g, '""')}"`,
              `"${off.lobbyistName.replace(/"/g, '""')}"`,
              `"${off.coveredPosition.replace(/"/g, '""')}"`,
              `"${agencies.replace(/"/g, '""')}"`,
              lf.amount,
              `"${issues.replace(/"/g, '""')}"`,
              lf.url,
            ].join(',')
          );
        }
      } else {
        rows.push(
          [
            'SENATE_LDA_FILING',
            lf.filingYear,
            lf.dtPosted,
            `"${lf.registrantName.replace(/"/g, '""')}"`,
            `"${lf.clientName.replace(/"/g, '""')}"`,
            'Registered Commercial Lobbyist (No Covered Gov Pos Disclosed)',
            'N/A',
            `"${agencies.replace(/"/g, '""')}"`,
            lf.amount,
            `"${issues.replace(/"/g, '""')}"`,
            lf.url,
          ].join(',')
        );
      }
    }
    for (const fr of sf.federalRegisterDocs) {
      rows.push(
        [
          'FEDERAL_REGISTER_NOTICE',
          fr.publicationDate.slice(0, 4) || 'N/A',
          fr.publicationDate,
          `"${(fr.agencies[0] || 'Federal Agency').replace(/"/g, '""')}"`,
          `"${matchedEntity.name.replace(/"/g, '""')}"`,
          'N/A',
          `"${fr.type.replace(/"/g, '""')}"`,
          `"${fr.agencies.join('; ').replace(/"/g, '""')}"`,
          0,
          `"${fr.title.slice(0, 120).replace(/"/g, '""')}"`,
          fr.url,
        ].join(',')
      );
    }
  }

  if (rows.length === 0) {
    rows.push(
      `NONE_DETECTED,N/A,N/A,"US Senate LDA / Federal Register","${matchedEntity.legalName.replace(/"/g, '""')}",None Indexed,None Indexed,None Indexed,0,"No direct Senate LDA lobbying or revolving-door covered official disclosures matched client name.",https://lda.senate.gov/`
    );
  }

  return `${header}\n${rows.join('\n')}\n`;
}

export function buildCyberExposureMarkdown(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined
): string {
  const cyber = liveIntel?.cyberTelemetry;
  if (!liveIntel || !cyber) {
    return `# SQUAD G — CYBER OPERATIONS & INFRASTRUCTURE EXPOSURE (${matchedEntity.name})
**Audit Mode:** Composite Sector Sweep (${matchedEntity.category}) · **Strict Passive OSINT Mode**

- Live passive DNS, BGP/ASN (RIPEstat), and Certificate Transparency (crt.sh) probing executes automatically when targeting a single operating business entity with a resolved corporate domain.
- See \`cyber/stix_attack_patterns.json\` for structured STIX 2.1 pattern serialization for ${matchedEntity.name}.
`;
  }

  return `# SQUAD G — CYBER OPERATIONS & INFRASTRUCTURE EXPOSURE (LIVE PASSIVE TELEMETRY)
**Audit Scope:** 10 Agents (G1–G10) · Cloudflare DoH, RIPEstat BGP/ASN, crt.sh Certificate Transparency, NIST NVD CVE 2.0
**Target Business:** ${liveIntel.entityName} (${liveIntel.legalName})
**Verified Domain:** ${cyber.primaryDomain || 'No public corporate domain resolved'}

---

## 1. EDGE DNS, MAIL AUTHENTICATION & CA AUTHORIZATION (CLOUDFLARE DoH)
- **Resolved Public IPv4 Addresses:** ${cyber.resolvedIps.length > 0 ? cyber.resolvedIps.join(', ') : 'None resolved'}
- **Authoritative Nameservers (NS):** ${cyber.nsRecords.length > 0 ? cyber.nsRecords.join(', ') : 'None resolved'}
- **Mail Exchangers (MX):** ${cyber.mxRecords.length > 0 ? cyber.mxRecords.join(' | ') : 'None resolved'}
- **SPF Anti-Spoofing Policy:** ${cyber.spfRecord ? `\`${cyber.spfRecord}\`` : 'MISSING / No TXT v=spf1 record observed'}
- **DMARC Policy (\`_dmarc\`):** ${cyber.dmarcRecord ? `\`${cyber.dmarcRecord}\`` : 'MISSING / No DMARC enforcement record detected'}
- **Certification Authority Authorization (CAA):** ${cyber.caaRecords.length > 0 ? cyber.caaRecords.join(' | ') : 'No restrictive CAA record published'}

## 2. BGP ROUTING, ASN OWNERSHIP & PEER TOPOLOGY (RIPESTAT)
${cyber.asnInfo.length > 0
  ? cyber.asnInfo
      .map(
        (a) =>
          `### AS${a.asn} — ${a.holder || 'Verified Network Operator'}
- **IPv4 / Routed Prefix:** \`${a.ip}\` within \`${a.prefix || 'Disclosed'}\`
- **Registry / Announced Prefixes:** ${a.rir} · **${a.announcedPrefixesCount}** announced prefixes
- **Observed Upstream / Peer Neighbours:** ${
            a.neighbourAsns.length > 0
              ? a.neighbourAsns.map((n) => `AS${n.asn} (${n.type})`).join(', ')
              : 'None returned in sample'
          }`
      )
      .join('\n\n')
  : '- No public ASN/BGP routing record queried (domain or public IPv4 unavailable).'}

## 3. CERTIFICATE TRANSPARENCY & SUBDOMAIN SURFACE (CRT.SH)
- **Certificates Sampled:** ${cyber.ctTotalCertsSampled}
- **Observed Certificate Authorities:** ${cyber.ctCertIssuers.length > 0 ? cyber.ctCertIssuers.join(', ') : 'None sampled'}
- **Observed Subdomains (${cyber.ctSubdomains.length}):** ${cyber.ctSubdomains.length > 0 ? cyber.ctSubdomains.map((s) => `\`${s}\``).join(', ') : 'None sampled within timeout/window'}

## 4. VULNERABILITIES (NIST NVD CVE 2.0) & SECURITY DISCLOSURE POLICY
- **\`/.well-known/security.txt\`:** ${cyber.securityTxtPresent ? `Present (${cyber.securityTxtContact || 'Contact configured'})` : 'Absent'}
- **\`robots.txt\` / \`llms.txt\`:** robots.txt=${cyber.robotsTxtPresent ? 'Present' : 'Absent'} · llms.txt=${cyber.llmsTxtPresent ? 'Present' : 'Absent'}
- **Product-Matched CVEs (${cyber.disclosedCves.length}):**
${cyber.disclosedCves.length > 0
  ? cyber.disclosedCves
      .map((c) => `  * **${c.cveId}** (${c.severity}${c.cvssScore !== null ? ` · CVSS ${c.cvssScore}` : ''} · ${c.published}): ${c.description} — ${c.source}`)
      .join('\n')
  : '  * Zero exact entity-matched CVEs returned by NIST NVD CVE 2.0 passive query.'}

## 5. OPEN-WEB CYBER INCIDENT, BREACH & OUTAGE COVERAGE (${cyber.cyberNewsHits.length})
${cyber.cyberNewsHits.length > 0
  ? cyber.cyberNewsHits
      .map((h, i) => `${i + 1}. **${h.title}** (${h.domain} · ${h.date}) — ${h.url}`)
      .join('\n')
  : '- No major cyber breach or outage headlines surfaced in open-web search.'}
`;
}

export function buildStix21BundleJson(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined,
  investigationId: string,
  timestampIso: string
): string {
  const cyber = liveIntel?.cyberTelemetry;
  const slug = matchedEntity.id.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase();
  const orgStixId = `identity--11111111-1111-4111-8111-${slug.padEnd(12, '0').slice(0, 12)}`;
  const objects: Array<Record<string, unknown>> = [
    {
      type: 'identity',
      spec_version: '2.1',
      id: orgStixId,
      created: timestampIso,
      modified: timestampIso,
      name: matchedEntity.legalName,
      identity_class: 'organization',
      sectors: [liveIntel?.industry || matchedEntity.category],
      description: `Target corporate entity investigated under ${investigationId}.`,
    },
  ];

  if (cyber?.primaryDomain) {
    const domId = `domain-name--22222222-2222-4222-8222-${slug.padEnd(12, '0').slice(0, 12)}`;
    const infraId = `infrastructure--33333333-3333-4333-8333-${slug.padEnd(12, '0').slice(0, 12)}`;
    objects.push({
      type: 'domain-name',
      spec_version: '2.1',
      id: domId,
      value: cyber.primaryDomain,
    });
    objects.push({
      type: 'infrastructure',
      spec_version: '2.1',
      id: infraId,
      created: timestampIso,
      modified: timestampIso,
      name: `${matchedEntity.name} Public Web & Edge Infrastructure`,
      infrastructure_types: ['hosting-target-lists'],
      description: `Resolved IPs: ${cyber.resolvedIps.join(', ') || 'None'}; DMARC=${cyber.dmarcRecord ? 'Configured' : 'Missing'}; Subdomains sampled=${cyber.ctSubdomains.length}.`,
    });
    objects.push({
      type: 'relationship',
      spec_version: '2.1',
      id: `relationship--44444444-4444-4444-8444-${slug.padEnd(12, '0').slice(0, 12)}`,
      created: timestampIso,
      modified: timestampIso,
      relationship_type: 'owns',
      source_ref: orgStixId,
      target_ref: infraId,
    });
  }

  cyber?.asnInfo.forEach((asn, idx) => {
    const asnHex = String(idx + 1).padStart(12, 'a');
    objects.push({
      type: 'autonomous-system',
      spec_version: '2.1',
      id: `autonomous-system--55555555-5555-4555-8555-${asnHex}`,
      number: Number(asn.asn.replace(/\D/g, '')) || 0,
      name: asn.holder || `AS${asn.asn}`,
      rir: asn.rir,
    });
  });

  cyber?.disclosedCves.forEach((cve, idx) => {
    const cveHex = String(idx + 1).padStart(12, 'c');
    const vulnId = `vulnerability--66666666-6666-4666-8666-${cveHex}`;
    objects.push({
      type: 'vulnerability',
      spec_version: '2.1',
      id: vulnId,
      created: timestampIso,
      modified: timestampIso,
      name: cve.cveId,
      description: cve.description,
      external_references: [
        { source_name: 'cve', external_id: cve.cveId, url: cve.source },
      ],
    });
    objects.push({
      type: 'relationship',
      spec_version: '2.1',
      id: `relationship--77777777-7777-4777-8777-${cveHex}`,
      created: timestampIso,
      modified: timestampIso,
      relationship_type: 'related-to',
      source_ref: vulnId,
      target_ref: orgStixId,
    });
  });

  const tlsCert = liveIntel?.deepAttackSurface?.tlsCertificate;
  if (tlsCert) {
    const certId = `x509-certificate--88888888-8888-4888-8888-${slug.padEnd(12, '0').slice(0, 12)}`;
    objects.push({
      type: 'x509-certificate',
      spec_version: '2.1',
      id: certId,
      is_self_signed: tlsCert.isSelfSigned,
      hashes: tlsCert.fingerprintSha256
        ? { 'SHA-256': tlsCert.fingerprintSha256.replace(/:/g, '').toLowerCase() }
        : undefined,
      serial_number: tlsCert.serialNumber || undefined,
      issuer: tlsCert.issuerCn || tlsCert.issuerOrg || undefined,
      subject: tlsCert.subjectCn || tlsCert.subjectOrg || undefined,
      validity_not_before: tlsCert.validFrom || undefined,
      validity_not_after: tlsCert.validTo || undefined,
      x509_v3_extensions: tlsCert.sanDomains.length > 0
        ? { subject_alternative_name: tlsCert.sanDomains.slice(0, 20).map((d) => `DNS:${d}`).join(', ') }
        : undefined,
    });
    objects.push({
      type: 'relationship',
      spec_version: '2.1',
      id: `relationship--88888888-8888-4888-9888-${slug.padEnd(12, '0').slice(0, 12)}`,
      created: timestampIso,
      modified: timestampIso,
      relationship_type: 'uses',
      source_ref: orgStixId,
      target_ref: certId,
    });
    tlsCert.sanDomains
      .filter((d) => d && !d.startsWith('*.') && d !== cyber?.primaryDomain)
      .slice(0, 12)
      .forEach((san, idx) => {
        const sanHex = String(idx + 1).padStart(12, 'd');
        objects.push({
          type: 'domain-name',
          spec_version: '2.1',
          id: `domain-name--88888888-8888-4888-a888-${sanHex}`,
          value: san,
        });
      });
  }

  return JSON.stringify(
    {
      type: 'bundle',
      id: `bundle--99999999-9999-4999-8999-${slug.padEnd(12, '0').slice(0, 12)}`,
      objects,
    },
    null,
    2
  );
}

export function buildSwarmAttributionMarkdown(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined,
  hawkes: HawkesAnalysisResult,
  stylo: StylometricResult,
  graph: ForensicPropertyGraphResult
): string {
  const events = liveIntel?.swarmTelemetry?.timestampedEvents || [];
  const domainFreq = new Map<string, number>();
  events.forEach((e) => {
    if (e.domain) domainFreq.set(e.domain, (domainFreq.get(e.domain) || 0) + 1);
  });
  const topDomains = Array.from(domainFreq.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  return `# SQUAD H — AUTONOMOUS SWARM, TEMPORAL BURSTINESS & SYBIL ATTRIBUTION
**Audit Scope:** 10 Agents (H1–H10) · Hawkes Inter-Arrival Math, Stylometric TTR, Louvain Modularity & k-Core Topology
**Target Entity:** ${matchedEntity.name} (${matchedEntity.legalName})

---

## 1. TEMPORAL BURSTINESS & HAWKES BRANCHING ANALYSIS
- **Verified Timestamped Events Sampled (N):** ${hawkes.eventCount}
- **Observation Span:** ${hawkes.spanHours} hours
- **Mean Inter-Arrival Time ($\mu$):** ${hawkes.meanInterArrivalHours} hours · **Std Dev ($\sigma$):** ${hawkes.stdDevInterArrivalHours} hours
- **Goh–Barabási Burstiness ($B$):** **${hawkes.burstinessCoefficient}** (range -1 regular to +1 extreme burst)
- **Estimated Self-Exciting Branching Ratio ($\\hat{n}$):** **${hawkes.branchingRatioEstimate}**
- **Synchronized <=2h Burst Pairs:** ${hawkes.shortWindowBurstPairs}
- **Mathematical Verdict:** ${hawkes.clusteringVerdict}

## 2. STYLOMETRIC CORPUS UNIFORMITY FINGERPRINT
- **Text Excerpts Audited:** ${stylo.sampleDocumentsCount}
- **Total Tokens / Unique Tokens:** ${stylo.totalTokens} / ${stylo.uniqueTokens}
- **Lexical Diversity (Type-Token Ratio):** **${stylo.typeTokenRatio}**
- **Mean Sentence Length / Burstiness:** ${stylo.meanSentenceLength} tokens / ${stylo.sentenceLengthBurstiness}
- **Templating / Uniformity Risk:** **${stylo.uniformityRisk}**
- **Repeated Meaningful Bigrams:** ${
    stylo.topRepeatedBigrams.length > 0
      ? stylo.topRepeatedBigrams.map((b) => `\`${b.bigram}\` (${b.count}x)`).join(', ')
      : 'None significant'
  }
- **Summary:** ${stylo.summary}

## 3. HETEROGENEOUS GRAPH MODULARITY & K-CORE TOPOLOGY
- **Graph Scale:** ${graph.nodes.length} nodes (7 entity/claim/ASN/person/contract/swarm types) · ${graph.edges.length} edges
- **Louvain Modularity ($Q$):** **${graph.modularityQ}** across **${graph.communityCount}** detected communities
- **Maximum k-Core Shell:** **${graph.maxKCore}**
- **Highest Betweenness Centrality Bridges:**
${graph.topCentralNodes.slice(0, 5).map((n, i) => `  ${i + 1}. **${n.label}** [${n.nodeType}] — Centrality=${n.betweennessCentrality}, Degree=${n.degree}, k-Core=${n.kCore}, Community=#${n.communityId}`).join('\n')}

## 4. AGENTIC SCRAPER & AI SURFACE GOVERNANCE
- **\`robots.txt\`:** ${liveIntel?.cyberTelemetry?.robotsTxtPresent ? 'Present' : 'Not detected'}
- **\`llms.txt\` (AI Agent Policy):** ${liveIntel?.cyberTelemetry?.llmsTxtPresent ? 'Present' : 'Not detected'}
- **\`/.well-known/security.txt\`:** ${liveIntel?.cyberTelemetry?.securityTxtPresent ? 'Present' : 'Not detected'}

## 5. TOP PROPAGATION & SOURCE DOMAINS OBSERVED
${topDomains.length > 0 ? topDomains.map(([dom, cnt]) => `- **${dom}**: ${cnt} timestamped signal(s)`).join('\n') : '- Insufficient multi-domain timestamped distribution in sample.'}
`;
}

export function buildHawkesMatrixJson(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined,
  hawkes: HawkesAnalysisResult,
  stylo: StylometricResult,
  graph: ForensicPropertyGraphResult,
  timestampIso: string
): string {
  return JSON.stringify(
    {
      target_entity: matchedEntity.name,
      generated_at: timestampIso,
      hawkes_temporal_metrics: hawkes,
      stylometric_fingerprint: stylo,
      graph_community_topology: {
        modularity_q: graph.modularityQ,
        community_count: graph.communityCount,
        max_k_core: graph.maxKCore,
        hidden_bridges: graph.hiddenBridges,
      },
      sampled_events: (liveIntel?.swarmTelemetry?.timestampedEvents || []).slice(0, 30),
    },
    null,
    2
  );
}

export function buildUnverifiedWatchlistMarkdown(
  matchedEntity: TechEntity,
  tribunal: AdversarialTribunalResult,
  timestampIso: string
): string {
  return `# UNVERIFIED INTELLIGENCE WATCHLIST (TRIBUNAL QUARANTINE)
**Target Entity:** ${matchedEntity.name} (${matchedEntity.legalName})
**Generated:** ${timestampIso}
**Protocol:** 3-Stage Dialectical Tribunal (Prosecutor -> Defense Red-Team -> Tribunal Judge)

This document strictly quarantines speculative leads, low-sample statistical signals ($N < 20$ or $N < 5$), and uncorroborated Tier-4 observations that did NOT meet the evidentiary threshold for promotion into \`06_FRAUD_AND_MONOPOLY_PATTERN_ANALYSIS.md\`.

---

## QUARANTINED ITEMS (${tribunal.unverifiedWatchlistItems.length})
${tribunal.unverifiedWatchlistItems.length > 0
  ? tribunal.unverifiedWatchlistItems
      .map(
        (item) => `### [${item.id}] ${item.signal_source}
- **Observed Hypothesis / Signal:** ${item.hypothesis}
- **Quarantine Justification:** ${item.quarantine_reason}
- **Required Corroboration to Promote:** ${item.required_corroboration}`
      )
      .join('\n\n')
  : '- Zero uncorroborated signals quarantined in this run.'}
`;
}

export function buildSanctionsExposureMarkdown(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined
): string {
  const s = liveIntel?.sanctionsTrade;
  if (!liveIntel || !s) {
    return `# SQUAD I — SANCTIONS, PEPS & PHYSICAL LOGISTICS EXPOSURE (${matchedEntity.name})
**Audit Mode:** Composite Sector Sweep (${matchedEntity.category}) · **Zero-Key Screening Threshold:** Jaro-Winkler >= 0.92

- Live OFAC/BIS Federal Register notices, PEP/Offshore references, FAA/Maritime registration leads, and USITC/Comtrade trade tariff screening execute automatically on single operating entity probes.
- See \`sanctions/entity_screening_ledger.json\` for structured screening records.
`;
  }

  return `# SQUAD I — SANCTIONS, PEPS & PHYSICAL LOGISTICS EXPOSURE (LIVE)
**Audit Scope:** 10 Agents (I1–I10) · OFAC SDN/BIS Federal Register (Jaro-Winkler >= 0.92), PEP/Offshore Leads, Aviation/Maritime & TBML Tariff Feeds
**Target Business:** ${liveIntel.entityName} (${liveIntel.legalName})
**Unique Entity & Affiliate Names Screened:** ${s.screenedNamesCount}
**Overall Screening Verdict:** ${s.screeningVerdict}

---

## 1. OFAC & BIS FEDERAL REGISTER SANCTIONS / EXPORT CONTROL NOTICES (${s.ofacBisNotices.length})
${s.ofacBisNotices.length > 0
  ? s.ofacBisNotices
      .map(
        (n, idx) =>
          `${idx + 1}. **${n.agency}** · Doc \`${n.documentNumber}\` (${n.publicationDate}) · Jaro-Winkler=\`${n.jaroWinklerScore}\`\n   - ${n.title}\n   - Source: ${n.url}`
      )
      .join('\n')
  : '- Zero direct Federal Register OFAC/BIS sanctions or denied-entity notices matched entity or affiliate names at Jaro-Winkler >= 0.92.'}

## 2. POLITICALLY EXPOSED PERSONS (PEP) & OFFSHORE LEAKS SCREENING (${s.pepAndOffshoreHits.length})
${s.pepAndOffshoreHits.length > 0
  ? s.pepAndOffshoreHits
      .map(
        (p, idx) =>
          `${idx + 1}. **${p.title}** (${p.source} · JW=${p.jaroWinklerScore})\n   - ${p.snippet}\n   - URL: ${p.url}`
      )
      .join('\n')
  : '- Zero high-confidence PEP or offshore registry paper links surfaced in live screening.'}

## 3. AVIATION (FAA) & MARITIME PHYSICAL LOGISTICS SIGNALS (${s.aviationMaritimeSignals.length})
${s.aviationMaritimeSignals.length > 0
  ? s.aviationMaritimeSignals.map((m, idx) => `${idx + 1}. **${m.title}** — ${m.snippet} (${m.url})`).join('\n')
  : '- No corporate aircraft tail numbers or vessel operator disclosures indexed in open search.'}

## 4. TRADE-BASED MONEY LAUNDERING (TBML) & HARMONIZED TARIFF SIGNALS (${s.tbmlTariffSignals.length})
${s.tbmlTariffSignals.length > 0
  ? s.tbmlTariffSignals.map((t, idx) => `${idx + 1}. **${t.title}** — ${t.snippet} (${t.url})`).join('\n')
  : '- No customs under/over-invoicing disputes or HTS trade notices surfaced.'}
`;
}

export function buildSanctionsLedgerJson(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined,
  timestampIso: string
): string {
  const s = liveIntel?.sanctionsTrade;
  return JSON.stringify(
    {
      target_entity: matchedEntity.name,
      legal_name: matchedEntity.legalName,
      generated_at: timestampIso,
      jaro_winkler_threshold: 0.92,
      screened_names_count: s?.screenedNamesCount || 1,
      screening_verdict: s?.screeningVerdict || 'COMPOSITE_MODE_NO_LIVE_SANCTIONS_MATCH',
      ofac_bis_notices: s?.ofacBisNotices || [],
      pep_and_offshore_hits: s?.pepAndOffshoreHits || [],
      aviation_maritime_signals: s?.aviationMaritimeSignals || [],
      tbml_tariff_signals: s?.tbmlTariffSignals || [],
    },
    null,
    2
  );
}

export function buildAccountingAuditMarkdown(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined
): string {
  const acc = liveIntel?.accountingForensics;
  if (!liveIntel || !acc) {
    return `# SQUAD J — QUANTITATIVE FORENSIC ACCOUNTING AUDIT (${matchedEntity.name})
**Audit Mode:** Composite Sector Sweep (${matchedEntity.category}) · **Statistical Gating:** Two-Period Consecutive XBRL Required

- Beneish M-Score, Altman Z-Score, Sloan Accrual Ratio (TATA), and strict $N \\ge 50$ 2nd-Digit Benford rounding audits compute directly from public SEC EDGAR \`companyfacts.json\` US-GAAP filings during single-entity investigations.
- See \`finance/forensic_ratios_matrix.json\` for structured telemetry.
`;
  }

  const ratios = acc.componentRatios || {};
  const ratioKeys = Object.keys(ratios);

  return `# SQUAD J — QUANTITATIVE FORENSIC ACCOUNTING, M-SCORE & ACCRUAL AUDIT (LIVE)
**Audit Scope:** 10 Agents (J1–J10) · SEC EDGAR XBRL US-GAAP (10-K/20-F Consecutive Fiscal Periods)
**Target Business:** ${liveIntel.entityName} (${liveIntel.legalName})
**Computation Status:** \`${acc.status}\` ${acc.currentYear && acc.priorYear ? `(FY${acc.priorYear} → FY${acc.currentYear})` : ''}
**Headline Verdict:** ${acc.summaryVerdict}

---

## 1. BENEISH 8-VARIABLE M-SCORE & MANIPULATION RISK
- **Computed Beneish M-Score:** ${acc.beneishMScore !== null ? `**${acc.beneishMScore}**` : 'UNAVAILABLE (Private entity or < 2 consecutive annual 10-K/20-F periods)'}
- **Threshold Benchmark:** \`-1.78\` (Scores > \`-1.78\` indicate elevated probability of earnings manipulation)
- **Classification Flag:** \`${acc.manipulationProbabilityFlag}\`
- **Sloan Accrual Ratio (TATA):** ${acc.sloanAccrualRatio !== null ? `**${acc.sloanAccrualRatio}**` : 'UNAVAILABLE'}

## 2. ALTMAN Z-SCORE INSOLVENCY ZONE
- **Computed Altman Z-Score:** ${acc.altmanZScore !== null ? `**${acc.altmanZScore}**` : 'UNAVAILABLE'}
- **Credit / Distress Zone:** \`${acc.altmanZone}\`

## 3. COMPONENT FINANCIAL RATIOS (${ratioKeys.length})
${ratioKeys.length > 0
  ? ratioKeys.map((k) => `- **${k}:** \`${ratios[k]}\``).join('\n')
  : '- Component GAAP ratios withheld cleanly due to private disclosure status or missing 2-year XBRL pairs.'}

## 4. SECOND-DIGIT BENFORD ROUNDING ANOMALY TEST (GATED N >= 50)
- **Sample Size (N):** ${acc.secondDigitBenford.sampleSize} figures ${acc.secondDigitBenford.sampleSize < 50 ? '(GATED: below N=50 minimum)' : '(ELIGIBLE)'}
- **Chi-Square Statistic:** ${acc.secondDigitBenford.chiSquare ?? 'Withheld (N < 50)'}
- **Mean Absolute Deviation (MAD):** ${acc.secondDigitBenford.mad ?? 'Withheld (N < 50)'}
- **Rounding Anomaly Detected:** \`${acc.secondDigitBenford.roundingAnomalyDetected}\`
`;
}

export function buildForensicRatiosMatrixJson(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined,
  timestampIso: string
): string {
  const acc = liveIntel?.accountingForensics;
  return JSON.stringify(
    {
      target_entity: matchedEntity.name,
      legal_name: matchedEntity.legalName,
      generated_at: timestampIso,
      status: acc?.status || 'INSUFFICIENT_DATA',
      current_year: acc?.currentYear || null,
      prior_year: acc?.priorYear || null,
      beneish_m_score: acc?.beneishMScore ?? null,
      manipulation_probability_flag: acc?.manipulationProbabilityFlag || 'UNAVAILABLE',
      altman_z_score: acc?.altmanZScore ?? null,
      altman_zone: acc?.altmanZone || 'UNAVAILABLE',
      sloan_accrual_ratio: acc?.sloanAccrualRatio ?? null,
      second_digit_benford: acc?.secondDigitBenford || {
        sampleSize: 0,
        chiSquare: null,
        mad: null,
        roundingAnomalyDetected: false,
      },
      component_ratios: acc?.componentRatios || {},
      summary_verdict: acc?.summaryVerdict || 'Awaiting 2-year SEC XBRL GAAP statements.',
    },
    null,
    2
  );
}

export function buildInsiderLaborMarkdown(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined
): string {
  const il = liveIntel?.insiderLabor;
  if (!liveIntel || !il) {
    return `# SQUAD K — INSIDER TRADING TIMING & WHISTLEBLOWER RETALIATION (${matchedEntity.name})
**Audit Mode:** Composite Sector Sweep (${matchedEntity.category})

- Live SEC Form 3/4/5/144 ownership filings, Form 8-K Items 4.01/4.02 auditor & restatement notices, CFPB consumer complaints, and OSHA/NLRB whistleblower retaliation checks run automatically on single-entity live searches.
`;
  }

  return `# SQUAD K — INSIDER TRADING TIMING, AUDITOR EXITS & WHISTLEBLOWER RETALIATION (LIVE)
**Audit Scope:** 10 Agents (K1–K10) · SEC EDGAR Forms 3/4/5/144 & 8-K (4.01/4.02), CFPB Complaint API, OSHA/NLRB Dockets
**Target Business:** ${liveIntel.entityName} (${liveIntel.legalName})
**Timing Analysis Summary:** ${il.preEventTimingNote}

---

## 1. SEC FORM 3 / 4 / 5 / 144 INSIDER OWNERSHIP FILINGS (${il.form4AndOwnershipFilings.length})
${il.form4AndOwnershipFilings.length > 0
  ? il.form4AndOwnershipFilings
      .slice(0, 12)
      .map((f, idx) => `${idx + 1}. **Form ${f.form}** (${f.filingDate}) — Accession \`${f.accessionNumber}\` — ${f.description} (${f.url})`)
      .join('\n')
  : '- Zero Form 3/4/5/144 insider ownership filings indexed in SEC EDGAR submissions.'}

## 2. SEC FORM 8-K ITEMS 4.01 (AUDITOR CHANGE) & 4.02 (NON-RELIANCE / RESTATEMENT) (${il.item4AuditorOrRestatement8Ks.length})
${il.item4AuditorOrRestatement8Ks.length > 0
  ? il.item4AuditorOrRestatement8Ks
      .map((k, idx) => `${idx + 1}. **${k.form}** (${k.filingDate}) · Items \`${k.items}\` · Accession \`${k.accessionNumber}\` (${k.url})`)
      .join('\n')
  : '- Zero Item 4.01 (Auditor Changes) or Item 4.02 (Non-Reliance Restatements) flagged in recent Form 8-K history.'}

## 3. CFPB CONSUMER FINANCIAL COMPLAINT DATABASE (TOTAL MATCHED: ${il.cfpbComplaintsTotal})
${il.cfpbSampleComplaints.length > 0
  ? il.cfpbSampleComplaints
      .map(
        (c, idx) =>
          `${idx + 1}. \`#${c.complaintId}\` (${c.dateReceived}) · **${c.product}** — ${c.issue} (Response: ${c.companyResponse}, Timely: ${c.timely})`
      )
      .join('\n')
  : '- No CFPB consumer financial complaints returned for this entity.'}

## 4. OSHA SAFETY & NLRB RETALIATION / LABOR DOCKETS (${il.oshaAndNlrbSignals.length})
${il.oshaAndNlrbSignals.length > 0
  ? il.oshaAndNlrbSignals.map((o, idx) => `${idx + 1}. **${o.title}** — ${o.snippet} (${o.url})`).join('\n')
  : '- Zero OSHA whistleblower or NLRB retaliation docket hits surfaced in open search.'}
`;
}

export function buildAdversarialAuditMarkdown(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined
): string {
  const adv = liveIntel?.adversarialInfra;
  if (!liveIntel || !adv) {
    return `# SQUAD L — STEALTH EDITS, BOTNET C2 & ADVERSARIAL AI AUDIT (${matchedEntity.name})
**Audit Mode:** Composite Sector Sweep (${matchedEntity.category})

- Live Internet Archive Wayback CDX digest-churn diffing, invisible Unicode tag (\`U+E0000–U+E007F\`) prompt-injection scanning, CISA KEV correlation, abuse.ch FeodoTracker/URLhaus lookups, and RIPEstat RPKI ROA route-origin validation execute on single-entity live investigations.
`;
  }

  return `# SQUAD L — STEALTH EDITS, BOTNET C2, RPKI & ADVERSARIAL AI AUDIT (LIVE)
**Audit Scope:** 10 Agents (L1–L10) · Wayback CDX Digests, Unicode Steganography Scanner, CISA KEV, Abuse.ch Feodo/URLhaus, RIPEstat RPKI ROA
**Target Business:** ${liveIntel.entityName} (${liveIntel.legalName})

---

## 1. INTERNET ARCHIVE WAYBACK CDX STEALTH-EDIT DIGEST CHURN
- **Snapshots Sampled:** ${adv.waybackSnapshotsFound} (${adv.earliestSnapshotTimestamp || 'N/A'} → ${adv.latestSnapshotTimestamp || 'N/A'})
- **Unique Content Digests:** ${adv.uniqueContentDigests}
- **High-Frequency Churn Detected:** \`${adv.highFrequencyChurnDetected}\`
${adv.sampleDigestTransitions.length > 0
  ? adv.sampleDigestTransitions
      .slice(0, 6)
      .map((t) => `  * \`${t.timestamp}\` · HTTP \`${t.statusCode}\` · Digest \`${t.digest.slice(0, 16)}...\``)
      .join('\n')
  : '  * No digest transition table available.'}

## 2. ADVERSARIAL AI PROMPT-INJECTION & UNICODE STEGANOGRAPHY SCAN
- **Threat Level:** \`${adv.adversarialPromptInjectionIndicators.threatLevel}\`
- **Invisible Unicode Tag Characters (U+E0000–U+E007F):** ${adv.adversarialPromptInjectionIndicators.invisibleUnicodeTagsCount}
- **Zero-Width Obfuscation Characters:** ${adv.adversarialPromptInjectionIndicators.zeroWidthCharsCount}
- **Suspicious Directive Patterns:** ${adv.adversarialPromptInjectionIndicators.suspiciousDirectivePatterns.length > 0 ? adv.adversarialPromptInjectionIndicators.suspiciousDirectivePatterns.join(', ') : 'None detected'}

## 3. CISA KNOWN EXPLOITED VULNERABILITIES (KEV) CORRELATION (${adv.cisaKevMatches.length})
${adv.cisaKevMatches.length > 0
  ? adv.cisaKevMatches
      .map(
        (k, idx) =>
          `${idx + 1}. **${k.cveId}** — ${k.vendorProject} ${k.product}: ${k.vulnerabilityName} (Added: ${k.dateAdded}, Due: ${k.dueDate}, Ransomware Use: \`${k.knownRansomwareCampaignUse}\`)`
      )
      .join('\n')
  : '- Zero product-matched CVEs appeared on the CISA Known Exploited Vulnerabilities (KEV) active exploit list.'}

## 4. ABUSE.CH URLHAUS & FEODOTRACKER BOTNET C2 INDICATORS (${adv.abuseChIndicators.length})
${adv.abuseChIndicators.length > 0
  ? adv.abuseChIndicators.map((a, idx) => `${idx + 1}. [${a.feed}] \`${a.indicator}\` — ${a.statusOrThreat} (${a.url})`).join('\n')
  : '- Zero domain or resolved IP matches returned from abuse.ch URLhaus or FeodoTracker C2 blocklists.'}

## 5. RIPESTAT RPKI ROA ROUTE-ORIGIN VALIDATION (${adv.rpkiValidation.length})
${adv.rpkiValidation.length > 0
  ? adv.rpkiValidation.map((r) => `- **AS${r.asn}** · Prefix \`${r.prefix}\` → RPKI Validity: \`${r.validity.toUpperCase()}\``).join('\n')
  : '- No public ASN/prefix resolved for RPKI validation.'}
`;
}

export function buildRejectedHypothesesJson(
  matchedEntity: TechEntity,
  tribunal: AdversarialTribunalResult,
  timestampIso: string
): string {
  return JSON.stringify(
    {
      target_entity: matchedEntity.name,
      generated_at: timestampIso,
      posterior_rejection_cutoff: 0.40,
      rejected_count: tribunal.rejectedCount,
      rejected_hypotheses: tribunal.rejectedHypotheses,
    },
    null,
    2
  );
}

export function buildEnvironmentalEpaMarkdown(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined
): string {
  const env = liveIntel?.environmentalEpa;
  if (!liveIntel || !env) {
    return `# SQUAD M — ENVIRONMENTAL, EPA ECHO & RESOURCE EXTRACTION (${matchedEntity.name})
**Audit Mode:** Composite Sector Sweep (${matchedEntity.category}) · **Sources:** US EPA ECHO CWA/CAA/RCRA & Federal Register

- Live EPA ECHO facility compliance audits (Clean Water Act, Clean Air Act, RCRA hazardous waste, and statutory USD penalties) execute automatically during single-entity live investigations.
`;
  }

  return `# SQUAD M — ENVIRONMENTAL, EPA ECHO & RESOURCE EXTRACTION AUDIT (LIVE)
**Audit Scope:** 10 Agents (M1–M10) · US EPA ECHO Facility Registry (CWA / CAA / RCRA), Statutory Penalties & PHMSA/FCC Extraction Notices
**Target Business:** ${liveIntel.entityName} (${liveIntel.legalName})
**Facilities Indexed:** ${env.epaFacilitiesCount} · **Total Assessed Penalties:** $${Math.round(env.totalPenaltiesUsd).toLocaleString('en-US')}
**Verdict:** ${env.environmentalVerdict}

---

## 1. US EPA ECHO FACILITY COMPLIANCE RECORDS (${env.facilities.length})
${env.facilities.length > 0
  ? env.facilities
      .map(
        (f, i) =>
          `${i + 1}. **${f.facilityName}** (\`${f.registryId}\` · ${f.city}, ${f.state})\n   - CWA Violations: \`${f.cwaViolations}\` · CAA Violations: \`${f.caaViolations}\` · RCRA Violations: \`${f.rcraViolations}\` · Penalties: \`$${f.penaltiesUsd.toLocaleString('en-US')}\` · Last Inspection: ${f.lastInspectionDate}\n   - Source: ${f.sourceUrl}`
      )
      .join('\n')
  : '- Zero matched industrial facilities returned by US EPA ECHO facility query.'}

## 2. FCC SPECTRUM, PHMSA PIPELINE & EXTRACTION NOTICES (${env.spectrumAndExtractionNotices.length})
${env.spectrumAndExtractionNotices.length > 0
  ? env.spectrumAndExtractionNotices.map((n, i) => `${i + 1}. **${n.title}** — ${n.snippet} (${n.url})`).join('\n')
  : '- Zero Federal Register FCC spectrum, PHMSA pipeline, or resource extraction notices matched.'}
`;
}

export function buildPatentGrantCaptureMarkdown(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined
): string {
  const pat = liveIntel?.patentGrantCapture;
  if (!liveIntel || !pat) {
    return `# SQUAD N — PATENT WARFARE, PTAB/SEP & BAYH-DOLE GRANT LAUNDERING (${matchedEntity.name})
**Audit Mode:** Composite Sector Sweep (${matchedEntity.category}) · **Sources:** OpenAlex, NIH RePORTER, NSF Awards, PTAB

- Taxpayer-funded research capture telemetry (NIH RePORTER, NSF Awards, OpenAlex academic lineage, and PTAB/FRAND SEP litigation) executes automatically on single-entity live searches.
`;
  }

  return `# SQUAD N — PATENT TROLLS, PTAB/SEP & ACADEMIC GRANT CAPTURE AUDIT (LIVE)
**Audit Scope:** 10 Agents (N1–N10) · OpenAlex Works, NIH RePORTER, NSF Awards & PTAB / Standard-Essential Patent Signals
**Target Business:** ${liveIntel.entityName} (${liveIntel.legalName})
**Verdict:** ${pat.grantCaptureVerdict}

---

## 1. FEDERAL RESEARCH GRANTS (NIH REPORTER & NSF BAYH-DOLE) (${pat.publicGrants.length})
- **Total NIH Matches:** ${pat.nihAwardsCount} · **Total NSF Matches:** ${pat.nsfAwardsCount}
${pat.publicGrants.length > 0
  ? pat.publicGrants
      .map(
        (g, i) =>
          `${i + 1}. [${g.agency}] \`${g.awardId}\` — **${g.title}** (Recipient: ${g.recipient} · $${Math.round(g.amountUsd).toLocaleString('en-US')} · ${g.startDate})\n   - Source: ${g.url}`
      )
      .join('\n')
  : '- Zero direct NIH or NSF federal award recipients matched target entity.'}

## 2. OPENALEX ACADEMIC PUBLICATION & INSTITUTIONAL PIPELINE (${pat.openAlexWorksCount} TOTAL WORKS)
${pat.academicWorks.length > 0
  ? pat.academicWorks
      .map(
        (w, i) =>
          `${i + 1}. **${w.title}** (${w.year ?? 'N/A'} · Citations: ${w.citedByCount}) · Institutions: ${w.institutions.join(', ') || 'Unlisted'} — ${w.url}`
      )
      .join('\n')
  : '- Zero affiliated OpenAlex academic works surfaced.'}

## 3. PTAB INTER PARTES REVIEW (IPR), SEP & NPE SIGNALS (${pat.ptabAndSepSignals.length})
${pat.ptabAndSepSignals.length > 0
  ? pat.ptabAndSepSignals.map((p, i) => `${i + 1}. **${p.title}** — ${p.snippet} (${p.url})`).join('\n')
  : '- Zero active PTAB invalidation or SEP/FRAND patent-troll signals surfaced in open web search.'}
`;
}

export function buildDarkPoolCryptoMarkdown(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined
): string {
  const dp = liveIntel?.darkPoolCrypto;
  const btcAnchor = liveIntel?.blockchainAnchor;
  if (!liveIntel || !dp) {
    return `# SQUAD O — DARK-POOL DERIVATIVES & CRYPTO TREASURY ROUTING (${matchedEntity.name})
**Audit Mode:** Composite Sector Sweep (${matchedEntity.category}) · **Sources:** SEC Form 13F-HR / NPORT-P & mempool.space

- Institutional 13F/NPORT stealth holding checks, Bitcoin mainnet block tip anchoring (mempool.space), and total-return swap signals run live on single-entity searches.
`;
  }

  return `# SQUAD O — DARK-POOL DERIVATIVES, 13F STEALTH BLOCKS & CRYPTO TREASURY AUDIT (LIVE)
**Audit Scope:** 10 Agents (O1–O10) · SEC EDGAR 13F-HR / NPORT-P, Live Bitcoin Mempool Chain Tip & Treasury Wrappers
**Target Business:** ${liveIntel.entityName} (${liveIntel.legalName})
**Verdict:** ${dp.derivativesVerdict}

---

## 1. SEC FORM 13F-HR & NPORT-P INSTITUTIONAL HOLDINGS (${dp.form13fAndNportFilings.length})
${dp.form13fAndNportFilings.length > 0
  ? dp.form13fAndNportFilings
      .map(
        (f, i) =>
          `${i + 1}. **Form ${f.form}** (${f.filedAt}) — ${f.entityName} · Accession \`${f.accessionNumber}\` — ${f.url}`
      )
      .join('\n')
  : '- Zero Form 13F-HR or NPORT-P institutional filings matched entity query.'}

## 2. LIVE BITCOIN MAINNET & MEMPOOL TELEMETRY (ZERO-KEY RING-2 ANCHOR)
- **Live Bitcoin Tip Height:** ${dp.mempoolTipHeight ? `#${dp.mempoolTipHeight}` : 'UNREACHABLE_OFFLINE'}
- **Live Bitcoin Tip Block Hash:** ${dp.mempoolTipHash ? `\`${dp.mempoolTipHash}\`` : 'UNREACHABLE_OFFLINE'}
- **Mempool Fastest Fee:** ${dp.fastestBitcoinFeeSatVb !== null ? `${dp.fastestBitcoinFeeSatVb} sat/vB` : 'N/A'}
- **Anchored Timestamp Status:** ${btcAnchor?.rfc3161Status || 'DEFERRED_TO_FINALIZE'} (${btcAnchor?.providerUrl || 'mempool.space'})

## 3. DARK-POOL ATS, TOTAL-RETURN SWAP & CRYPTO TREASURY SIGNALS (${dp.swapAndTreasurySignals.length})
${dp.swapAndTreasurySignals.length > 0
  ? dp.swapAndTreasurySignals.map((s, i) => `${i + 1}. **${s.title}** — ${s.snippet} (${s.url})`).join('\n')
  : '- Zero verified dark-pool ATS, synthetic swap, or digital-asset treasury reserve headlines surfaced.'}
`;
}

export function buildLegalSlappMarkdown(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined
): string {
  const jud = liveIntel?.legalSlappBankruptcy;
  if (!liveIntel || !jud) {
    return `# SQUAD P — LEGAL SLAPP WARFARE, FORCED ARBITRATION & JUDGE/FORUM SHOPPING (${matchedEntity.name})
**Audit Mode:** Composite Sector Sweep (${matchedEntity.category}) · **Source:** CourtListener REST v4 API

- Live federal docket harvesting, judge/district forum concentration analysis, SLAPP intimidation, and forced-arbitration tracking run automatically on single-entity investigations.
`;
  }

  return `# SQUAD P — LEGAL SLAPP WARFARE, FORCED ARBITRATION & JUDGE/FORUM SHOPPING (LIVE)
**Audit Scope:** 10 Agents (P1–P10) · CourtListener REST v4 Federal Dockets, Venue Concentration & Chapter 11 Shielding
**Target Business:** ${liveIntel.entityName} (${liveIntel.legalName})
**CourtListener Matched Dockets:** ${jud.courtListenerDocketsCount}
**Verdict:** ${jud.judicialVerdict}

---

## 1. COURTLISTENER REST v4 FEDERAL JUDICIAL DOCKETS (${jud.courtDockets.length})
${jud.courtDockets.length > 0
  ? jud.courtDockets
      .map(
        (d, i) =>
          `${i + 1}. **${d.caseName}** (\`${d.docketNumber}\` · ${d.court} · Filed ${d.dateFiled})\n   - Judge: ${d.judgeAssigned} · Nature of Suit: ${d.suitNature}\n   - Docket URL: ${d.url}`
      )
      .join('\n')
  : '- Zero direct federal judicial dockets matched exact entity search in CourtListener REST v4.'}

## 2. FORUM & VENUE SHOPPING CONCENTRATION
${jud.forumConcentration.length > 0
  ? jud.forumConcentration.map((f) => `- **${f.court}**: ${f.count} docket(s)`).join('\n')
  : '- Insufficient multi-docket volume to compute court venue clustering.'}

## 3. SLAPP RETALIATION, FORCED ARBITRATION & TEXAS TWO-STEP SIGNALS (${jud.slappAndArbitrationSignals.length})
${jud.slappAndArbitrationSignals.length > 0
  ? jud.slappAndArbitrationSignals.map((s, i) => `${i + 1}. **${s.title}** — ${s.snippet} (${s.url})`).join('\n')
  : '- Zero SLAPP defamation suits, forced arbitration disputes, or divisive Chapter 11 liability-shield hits surfaced.'}
`;
}

export function buildBftCorroborationLedgerJson(
  matchedEntity: TechEntity,
  liveIntel: LiveBusinessIntelligence | undefined,
  bft: BftCorroborationSummary,
  timestampIso: string
): string {
  return JSON.stringify(
    {
      target_entity: matchedEntity.name,
      legal_name: matchedEntity.legalName,
      generated_at: timestampIso,
      ring_1_adversarial_shield: {
        quorum_rule: bft.quorumRule,
        statutory_root_sources_count: bft.statutoryRootSourcesCount,
        untrusted_ingress_count: bft.untrustedIngressCount,
        corroborated_fact_ratio: bft.corroboratedFactRatio,
        quarantined_single_source_claims: bft.quarantinedSingleSourceClaims,
        sanitized_unicode_prompt_traps: bft.sanitizedPromptTrapsCount,
        stream_bomb_truncations: bft.streamBombTruncationsCount,
      },
      blockchain_and_rfc3161_anchor: liveIntel?.blockchainAnchor || {
        bitcoinBlockHash: null,
        bitcoinBlockHeight: null,
        anchoredAtIso: timestampIso,
        providerUrl: 'offline_composite_mode',
        rfc3161Status: 'UNREACHABLE_OFFLINE',
      },
    },
    null,
    2
  );
}

export function buildVerifyDossierMjs(): string {
  return `#!/usr/bin/env node
/**
 * Sovereign Dossier Offline Cryptographic Verifier (Zero Dependencies)
 * Verifies:
 *   1. 100% FIPS 180-4 SHA-256 parity across SHA256SUMS
 *   2. Deterministic Binary Merkle Tree Root & Inclusion Proofs
 *   3. RFC 8032 Ed25519 digital signature via PUBLIC_KEY.pem
 *   4. Zero orphaned [CLM-*] Claim-to-Evidence pointers (byte bounds + RFC 6901 JSON Pointers)
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const rootDir = process.cwd();
let failures = 0;

function pass(msg) { console.log('\\x1b[32m[PASS]\\x1b[0m ' + msg); }
function fail(msg) { console.error('\\x1b[31m[FAIL]\\x1b[0m ' + msg); failures++; }

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function resolveJsonPointer(obj, pointer) {
  if (!pointer || pointer === '/') return obj;
  if (!pointer.startsWith('/')) throw new Error('Invalid JSON pointer: ' + pointer);
  const parts = pointer.slice(1).split('/').map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'));
  let cur = obj;
  for (const seg of parts) {
    if (cur === null || typeof cur !== 'object' || !(seg in cur)) {
      throw new Error('Missing JSON pointer segment: ' + seg + ' in ' + pointer);
    }
    cur = cur[seg];
  }
  return cur;
}

// 1. Verify SHA256SUMS
const sumsPath = path.join(rootDir, 'SHA256SUMS');
if (!fs.existsSync(sumsPath)) {
  fail('Missing SHA256SUMS manifest');
  process.exit(1);
}
const sumLines = fs.readFileSync(sumsPath, 'utf8').trim().split(/\\r?\\n/).filter(Boolean);
const verifiedHashesByPath = new Map();

for (const line of sumLines) {
  const m = line.match(/^([a-f0-9]{64})\\s+(.+)$/);
  if (!m) { fail('Malformed SHA256SUMS line: ' + line); continue; }
  const expected = m[1];
  const relPath = m[2].trim();
  const absPath = path.join(rootDir, relPath);
  if (!fs.existsSync(absPath)) { fail('Missing file listed in SHA256SUMS: ' + relPath); continue; }
  const actual = sha256Hex(fs.readFileSync(absPath));
  if (actual !== expected) {
    fail('SHA-256 mismatch on ' + relPath + ' (expected ' + expected.slice(0, 12) + ', got ' + actual.slice(0, 12) + ')');
  } else {
    verifiedHashesByPath.set(relPath, actual);
  }
}
if (verifiedHashesByPath.size === sumLines.length && sumLines.length > 0) {
  pass('Verified 100% FIPS 180-4 SHA-256 checksums across all ' + verifiedHashesByPath.size + ' dossier artifacts');
}

// 2. Verify Binary Merkle Tree Root
const ledgerPath = path.join(rootDir, 'LEDGER_ENTRY.json');
if (!fs.existsSync(ledgerPath)) {
  fail('Missing LEDGER_ENTRY.json');
  process.exit(1);
}
const ledger = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'));
const excluded = new Set(ledger.merkle_excluded_files || ['LEDGER_ENTRY.json', 'artifact-index.json', 'SHA256SUMS', 'verify_dossier.mjs']);
let leafHashes = [];
if (ledger.merkle_scope === 'all_dossier_artifacts') {
  for (const [rel, h] of verifiedHashesByPath.entries()) {
    if (!excluded.has(rel)) leafHashes.push(h);
  }
} else {
  for (const [rel, h] of verifiedHashesByPath.entries()) {
    if (rel.startsWith('evidence/') || rel.startsWith('raw/')) leafHashes.push(h);
  }
}
const sortedLeaves = [...leafHashes].sort();
let level = [...sortedLeaves];
if (level.length === 0) level = [sha256Hex(Buffer.from('EMPTY_MERKLE_TREE'))];
while (level.length > 1) {
  const next = [];
  for (let i = 0; i < level.length; i += 2) {
    const left = level[i];
    const right = i + 1 < level.length ? level[i + 1] : level[i];
    next.push(sha256Hex(Buffer.from(left + right, 'utf8')));
  }
  level = next;
}
const recomputedRoot = level[0];
const expectedRoot = ledger.merkle_root || ledger.merkle_root_sha256;
if (recomputedRoot === expectedRoot) {
  pass('Recomputed Binary Merkle Root matches LEDGER_ENTRY.json (' + recomputedRoot.slice(0, 20) + '..., ' + sortedLeaves.length + ' leaves)');
} else {
  fail('Merkle Root mismatch! Expected ' + expectedRoot + ' got ' + recomputedRoot);
}

// 3. Verify Merkle Inclusion Proofs if present
if (Array.isArray(ledger.merkle_inclusion_proofs) && ledger.merkle_inclusion_proofs.length > 0) {
  let proofOk = 0;
  for (const item of ledger.merkle_inclusion_proofs) {
    let cur = item.leaf_sha256;
    for (const step of item.proof || []) {
      cur = step.position === 'left'
        ? sha256Hex(Buffer.from(step.sibling + cur, 'utf8'))
        : sha256Hex(Buffer.from(cur + step.sibling, 'utf8'));
    }
    if (cur === expectedRoot) proofOk++;
    else fail('Merkle inclusion proof failed for ' + item.path);
  }
  if (proofOk === ledger.merkle_inclusion_proofs.length) {
    pass('Verified ' + proofOk + ' Merkle Inclusion Proof paths to root');
  }
}

// 4. Verify RFC 8032 Ed25519 Signature
const pubPemPath = path.join(rootDir, 'PUBLIC_KEY.pem');
const pubPem = fs.existsSync(pubPemPath) ? fs.readFileSync(pubPemPath, 'utf8') : ledger.ed25519_public_key_pem;
const signedMsg = ledger.signed_payload || expectedRoot;
if (pubPem && ledger.ed25519_signature) {
  try {
    const ok = crypto.verify(null, Buffer.from(signedMsg, 'utf8'), pubPem, Buffer.from(ledger.ed25519_signature, 'hex'));
    if (ok) pass('RFC 8032 Ed25519 signature verified against PUBLIC_KEY.pem');
    else fail('Ed25519 signature verification returned false');
  } catch (err) {
    fail('Ed25519 signature verification error: ' + err.message);
  }
} else {
  fail('Missing Ed25519 public key or signature in dossier');
}

// 5. Verify Claim-to-Evidence Pointer Integrity (0 orphaned claims across raw/*.md)
const rawDir = path.join(rootDir, 'raw');
let totalClaims = 0;
let orphanedClaims = 0;
if (fs.existsSync(rawDir)) {
  const rawFiles = fs.readdirSync(rawDir).filter((f) => f.endsWith('.md'));
  for (const rf of rawFiles) {
    const text = fs.readFileSync(path.join(rawDir, rf), 'utf8');
    const jsonMatch = text.match(/\\\`\\\`\\\`json\\r?\\n([\\s\\S]*?)\\r?\\n\\\`\\\`\\\`/);
    if (!jsonMatch) continue;
    let claims = [];
    try { claims = JSON.parse(jsonMatch[1]); } catch { fail('Invalid claim JSON in raw/' + rf); continue; }
    for (const c of claims) {
      totalClaims++;
      const srcAbs = path.join(rootDir, c.source_path);
      if (!fs.existsSync(srcAbs)) {
        orphanedClaims++;
        fail('Orphaned claim ' + c.claim_id + ': missing source ' + c.source_path);
        continue;
      }
      const srcBuf = fs.readFileSync(srcAbs);
      if (sha256Hex(srcBuf) !== c.source_sha256) {
        orphanedClaims++;
        fail('Hash mismatch on claim ' + c.claim_id + ' -> ' + c.source_path);
        continue;
      }
      if (c.json_pointer) {
        try {
          resolveJsonPointer(JSON.parse(srcBuf.toString('utf8')), c.json_pointer);
        } catch (err) {
          orphanedClaims++;
          fail('Broken JSON Pointer in ' + c.claim_id + ': ' + err.message);
        }
      }
    }
  }
}
if (totalClaims > 0 && orphanedClaims === 0) {
  pass('Verified ' + totalClaims + ' Claim-to-Evidence links across raw/*.md (0 orphaned claims)');
} else if (totalClaims === 0) {
  fail('No claims found in raw/*.md');
}

// 5b. Verify Ring-3 IPFS CIDv1 & Ring-2 Bitcoin Anchor Format (if present)
const IPFS_B32 = 'abcdefghijklmnopqrstuvwxyz234567';
function computeLocalIpfsCidV1(digestHex) {
  const hex = String(digestHex || '').trim().toLowerCase();
  const digestBytes = /^[0-9a-f]{64}$/.test(hex)
    ? Buffer.from(hex, 'hex')
    : crypto.createHash('sha256').update(String(digestHex || '')).digest();
  const cidBytes = Buffer.concat([Buffer.from([0x01, 0x55, 0x12, 0x20]), digestBytes]);
  let bits = 0;
  let value = 0;
  let out = 'b';
  for (let i = 0; i < cidBytes.length; i++) {
    value = (value << 8) | cidBytes[i];
    bits += 8;
    while (bits >= 5) {
      out += IPFS_B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += IPFS_B32[(value << (5 - bits)) & 31];
  return out;
}

if (ledger.ipfs_cidv1) {
  const expectedCid = computeLocalIpfsCidV1(expectedRoot);
  if (ledger.ipfs_cidv1 === expectedCid) {
    pass('Ring-3 IPFS CIDv1 matches deterministic Merkle Root encoding (' + expectedCid + ')');
  } else {
    fail('IPFS CIDv1 mismatch! Expected ' + expectedCid + ' got ' + ledger.ipfs_cidv1);
  }
}

if (ledger.bitcoin_anchor && ledger.bitcoin_anchor.bitcoinBlockHash) {
  if (/^[0-9a-f]{64}$/i.test(ledger.bitcoin_anchor.bitcoinBlockHash)) {
    pass('Ring-2 Bitcoin Anchor tip hash validated (Block #' + ledger.bitcoin_anchor.bitcoinBlockHeight + ')');
  } else {
    fail('Invalid Bitcoin block hash format in LEDGER_ENTRY.json');
  }
}

// 5c. Verify RFC 3161 Legal Timestamping Receipt (MERKLE_ROOT.tsr or MERKLE_ROOT.tsr.status.json)
const tsrPath = path.join(rootDir, 'MERKLE_ROOT.tsr');
const tsrStatusPath = path.join(rootDir, 'MERKLE_ROOT.tsr.status.json');
if (fs.existsSync(tsrPath)) {
  const tsrBuf = fs.readFileSync(tsrPath);
  const tsrSha256 = sha256Hex(tsrBuf);
  const sumSha = verifiedHashesByPath.get('MERKLE_ROOT.tsr');
  if (tsrBuf.length <= 64 || tsrBuf[0] !== 0x30) {
    fail('MERKLE_ROOT.tsr is not a valid ASN.1 DER TimeStampResp (' + tsrBuf.length + ' bytes)');
  } else if (!sumSha || sumSha !== tsrSha256) {
    fail('MERKLE_ROOT.tsr is missing or mismatched in SHA256SUMS');
  } else if (ledger.rfc3161_tsa_anchor && ledger.rfc3161_tsa_anchor.token_sha256 && ledger.rfc3161_tsa_anchor.token_sha256 !== tsrSha256) {
    fail('MERKLE_ROOT.tsr SHA-256 does not match LEDGER_ENTRY.json rfc3161_tsa_anchor.token_sha256');
  } else {
    pass('RFC 3161 DER receipt MERKLE_ROOT.tsr verified (' + tsrBuf.length + 'B · SHA256:' + tsrSha256.slice(0, 12) + ')');
  }
} else if (fs.existsSync(tsrStatusPath)) {
  try {
    const statusObj = JSON.parse(fs.readFileSync(tsrStatusPath, 'utf8'));
    const sumSha = verifiedHashesByPath.get('MERKLE_ROOT.tsr.status.json');
    if (!sumSha) {
      fail('MERKLE_ROOT.tsr.status.json is not bound in SHA256SUMS');
    } else {
      pass('RFC 3161 TSA diagnostic receipt MERKLE_ROOT.tsr.status.json verified (status=' + (statusObj.status || 'UNREACHABLE_OFFLINE') + ', attempts=' + (Array.isArray(statusObj.attempts) ? statusObj.attempts.length : 0) + ')');
    }
  } catch (err) {
    fail('Invalid MERKLE_ROOT.tsr.status.json: ' + err.message);
  }
}

// 5d. Verify v26.0 zkTLS Provenance Manifest / .tlsn.json Receipts, FollowTheMoney NDJSON & Phase-5 ACH Matrix
const zktlsManifestPath = path.join(rootDir, 'evidence', 'zktls_proofs', 'zktls_provenance_manifest.json');
if (fs.existsSync(zktlsManifestPath)) {
  try {
    const zktlsManifest = JSON.parse(fs.readFileSync(zktlsManifestPath, 'utf8'));
    const status = String(zktlsManifest.zktlsProvenanceStatus || zktlsManifest.ZKTLS_PROVENANCE_STATUS || 'UNKNOWN');
    const receipts = Array.isArray(zktlsManifest.receipts) ? zktlsManifest.receipts : [];
    let proofFilesChecked = 0;
    for (const r of receipts) {
      if (r.status === 'VERIFIED_TLSN_PROOF' && r.proofFilename) {
        const rel = 'evidence/zktls_proofs/' + r.proofFilename;
        if (!verifiedHashesByPath.has(rel)) {
          fail('Verified zkTLS proof file missing from SHA256SUMS: ' + rel);
        } else {
          proofFilesChecked++;
        }
      }
    }
    pass('v26.0 zkTLS Provenance audited (status=' + status + ', verified_tlsn_proofs=' + proofFilesChecked + '/' + receipts.length + ')');
  } catch (err) {
    fail('Invalid evidence/zktls_proofs/zktls_provenance_manifest.json: ' + err.message);
  }
}

const ftmPath = path.join(rootDir, 'evidence', 'followthemoney_graph.ftm.json');
if (fs.existsSync(ftmPath)) {
  try {
    const lines = fs.readFileSync(ftmPath, 'utf8').trim().split(/\\r?\\n/).filter(Boolean);
    for (const line of lines) {
      const obj = JSON.parse(line);
      if (!obj.id || !obj.schema || !obj.properties) throw new Error('Missing required FtM fields (id/schema/properties)');
    }
    pass('Verified FollowTheMoney NDJSON export (' + lines.length + ' valid FtM entities)');
  } catch (err) {
    fail('Invalid FollowTheMoney NDJSON in evidence/followthemoney_graph.ftm.json: ' + err.message);
  }
}

const achPath = path.join(rootDir, 'evidence', 'ach_red_team_matrix.json');
if (fs.existsSync(achPath)) {
  try {
    const achObj = JSON.parse(fs.readFileSync(achPath, 'utf8'));
    if (typeof achObj.preRedTeamPosterior !== 'number' || typeof achObj.postRedTeamPosterior !== 'number') {
      fail('Phase-5 ACH matrix missing preRedTeamPosterior/postRedTeamPosterior');
    } else {
      pass('Verified Phase-5 Adversarial Red-Team ACH Matrix (' + (achObj.survivedCount || 0) + '/' + (achObj.totalFindingsEvaluated || 0) + ' survived · posterior ' + (achObj.preRedTeamPosterior * 100).toFixed(1) + '% -> ' + (achObj.postRedTeamPosterior * 100).toFixed(1) + '%)');
    }
  } catch (err) {
    fail('Invalid evidence/ach_red_team_matrix.json: ' + err.message);
  }
}

if (failures > 0) {
  console.error('\\nVERIFICATION FAILED with ' + failures + ' error(s).');
  process.exit(1);
}
console.log('\\nALL CRYPTOGRAPHIC & EVIDENTIARY CHECKS PASSED.');
`;
}

export interface WorkbenchPayload {
  meta: {
    investigationId: string;
    entityName: string;
    legalName: string;
    fri: number;
    mai: number;
    merkleRoot: string;
    merkleLeaves: number;
    modularityQ: number;
    maxKCore: number;
    benfordVerdict: string;
    hawkesVerdict: string;
    ed25519SignerFingerprint?: string;
    ipfsCidV1?: string;
    bitcoinBlockHeight?: number | null;
  };
  filesMap: Record<string, string>;
  fileList: string[];
  claimsIndex: Record<string, {
    claim_id: string;
    agent_id: string;
    source_path: string;
    source_sha256: string;
    json_pointer?: string;
    byte_offset_start: number;
    byte_offset_end: number;
    truth_tier: number;
    corroboration_score: number;
  }>;
  graphNodes: PropertyGraphNode[];
  graphEdges: PropertyGraphEdge[];
  hiddenBridges: ForensicPropertyGraphResult['hiddenBridges'];
  topCentralNodes: ForensicPropertyGraphResult['topCentralNodes'];
  timelineRows: Array<{ period: string; phase: string; milestone: string; impact: string; source: string }>;
  contradictions: AdversarialTribunalResult['arbitrationEntries'];
}

export function buildWorkbenchHtml(entityName: string, investigationId: string, fri: number, mai: number, merkleRoot: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sovereign 160-Agent Forensic Workbench: ${entityName}</title>
  <link rel="stylesheet" href="viewer.css">
</head>
<body>
  <header class="header">
    <div>
      <h1>SOVEREIGN 160-AGENT FORENSIC WORKBENCH: ${entityName}</h1>
      <div class="meta">ID: ${investigationId} | FRI: ${fri.toFixed(2)} | MAI: ${mai.toFixed(2)} | Merkle: ${merkleRoot.slice(0, 16)}... | Ed25519 + IPFS + BTC Sealed | Offline file:// Mode</div>
    </div>
    <div class="badges" id="statsBadges"></div>
  </header>

  <div class="workbench">
    <section class="left-pane">
      <div class="toolbar">
        <span class="toolbar-title">Multi-Layer Forensic Graph (16 Squads · A–P)</span>
        <div class="layer-toggles" id="layerToggles">
          <button data-layer="all" class="active">All Layers</button>
          <button data-layer="ownership">Ownership / SPV</button>
          <button data-layer="revolving_door">Revolving Door</button>
          <button data-layer="cyber">Cyber / ASN</button>
          <button data-layer="swarm">AI Swarm</button>
          <button data-layer="sanctions_trade">Sanctions / Trade</button>
          <button data-layer="accounting_insider">Accounting / Insider</button>
          <button data-layer="adversarial">Adversarial / RPKI</button>
          <button data-layer="environmental">EPA / Extraction</button>
          <button data-layer="patents_grants">Patents / Grants</button>
          <button data-layer="derivatives_crypto">13F / Dark-Pool</button>
          <button data-layer="judicial_slapp">Court / SLAPP</button>
        </div>
      </div>

      <div class="path-finder-bar">
        <span class="pf-label">Collusion Path Finder:</span>
        <select id="pathFromSelect"></select>
        <span class="pf-arrow">→</span>
        <select id="pathToSelect"></select>
        <button id="tracePathBtn" type="button">Trace Shortest Path</button>
        <button id="clearPathBtn" type="button" class="secondary">Clear</button>
      </div>
      <div id="pathResultBanner" class="path-result hidden"></div>

      <div class="canvas-wrap">
        <canvas id="graphCanvas"></canvas>
        <div id="nodeTooltip" class="tooltip hidden"></div>
      </div>
      <div class="bridges-panel" id="bridgesPanel">
        <div class="panel-heading">Top Brandes Centrality Nodes &amp; Shortest-Path Hidden Bridges</div>
        <div id="bridgesContent" class="bridges-grid"></div>
      </div>
    </section>

    <section class="right-pane">
      <div class="tab-bar">
        <button class="tab-btn active" data-tab="files">Dossier Files &amp; Evidence Drawer</button>
        <button class="tab-btn" data-tab="timeline">Timeline</button>
        <button class="tab-btn" data-tab="tribunal">Bayesian Tribunal &amp; Contradictions</button>
      </div>

      <div id="tab-files" class="tab-panel active">
        <div class="files-split">
          <div class="sidebar">
            <input type="text" id="fileFilter" placeholder="Filter files (e.g. 20_, sanctions, raw/)..." />
            <div id="fileList"></div>
          </div>
          <div class="file-viewer">
            <div class="file-header" id="currentFileName">00_EXEC_SUMMARY.md</div>
            <div class="content-scroll">
              <pre id="contentArea">Loading offline dossier...</pre>
            </div>
            <div id="claimDrawer" class="claim-drawer hidden">
              <div class="claim-drawer-head">
                <span id="claimDrawerTitle">Evidence Byte-Offset &amp; JSON Pointer Inspector</span>
                <button id="closeClaimDrawer" type="button">Close</button>
              </div>
              <div id="claimDrawerBody" class="claim-drawer-body"></div>
            </div>
          </div>
        </div>
      </div>

      <div id="tab-timeline" class="tab-panel">
        <div class="panel-scroll" id="timelineContainer"></div>
      </div>

      <div id="tab-tribunal" class="tab-panel">
        <div class="panel-scroll" id="tribunalContainer"></div>
      </div>
    </section>
  </div>

  <script src="workbench_data.js"></script>
  <script src="viewer.js"></script>
</body>
</html>`;
}

export function buildWorkbenchCss(): string {
  return `* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #080b12; color: #e2e8f0; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
.header { background: #0f1523; padding: 12px 20px; border-bottom: 1px solid #1e293b; display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.header h1 { font-size: 14px; color: #f59e0b; letter-spacing: 0.8px; text-transform: uppercase; }
.header .meta { font-size: 11px; color: #94a3b8; margin-top: 3px; font-family: monospace; }
.badges { display: flex; gap: 8px; flex-wrap: wrap; }
.badge { background: #1e293b; border: 1px solid #334155; padding: 4px 8px; border-radius: 4px; font-size: 11px; color: #cbd5e1; }
.workbench { flex: 1; display: grid; grid-template-columns: 1fr 1.15fr; overflow: hidden; }
.left-pane { display: flex; flex-direction: column; border-right: 1px solid #1e293b; overflow: hidden; background: #0b0e17; }
.toolbar { padding: 8px 14px; background: #0f1523; border-bottom: 1px solid #1e293b; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
.toolbar-title { font-size: 11px; font-weight: bold; color: #fbbf24; text-transform: uppercase; }
.layer-toggles { display: flex; gap: 4px; flex-wrap: wrap; }
.layer-toggles button { padding: 4px 8px; font-size: 10.5px; font-family: monospace; background: #111827; border: 1px solid #334155; color: #94a3b8; border-radius: 4px; cursor: pointer; }
.layer-toggles button.active { background: #f59e0b; color: #090d16; border-color: #f59e0b; font-weight: bold; }
.path-finder-bar { padding: 6px 14px; background: #0b1120; border-bottom: 1px solid #1e293b; display: flex; align-items: center; gap: 6px; flex-wrap: wrap; font-size: 11px; }
.pf-label { color: #fb7185; font-weight: bold; font-size: 10.5px; text-transform: uppercase; }
.pf-arrow { color: #94a3b8; }
.path-finder-bar select { max-width: 170px; background: #090d16; border: 1px solid #334155; color: #e2e8f0; padding: 3px 6px; border-radius: 4px; font-size: 11px; font-family: monospace; }
.path-finder-bar button { padding: 3px 8px; background: #ff1e56; border: 1px solid #ff1e56; color: #fff; border-radius: 4px; font-size: 10.5px; font-family: monospace; font-weight: bold; cursor: pointer; }
.path-finder-bar button.secondary { background: #1e293b; border-color: #334155; color: #cbd5e1; font-weight: normal; }
.path-result { padding: 6px 14px; background: rgba(255, 30, 86, 0.14); border-bottom: 1px solid #ff1e56; font-size: 11px; color: #fecdd3; font-family: monospace; }
.path-result.hidden { display: none; }
.canvas-wrap { flex: 1; position: relative; overflow: hidden; }
canvas { width: 100%; height: 100%; display: block; cursor: grab; }
.tooltip { position: absolute; left: 12px; bottom: 12px; max-width: 92%; background: rgba(15, 21, 35, 0.95); border: 1px solid #f59e0b; border-radius: 6px; padding: 10px 12px; font-size: 11px; line-height: 1.4; pointer-events: none; }
.tooltip.hidden { display: none; }
.bridges-panel { max-height: 170px; overflow-y: auto; border-top: 1px solid #1e293b; background: #0f1523; padding: 10px 14px; }
.panel-heading { font-size: 11px; font-weight: bold; color: #fbbf24; margin-bottom: 6px; text-transform: uppercase; }
.bridges-grid { display: grid; gap: 5px; font-size: 11px; color: #cbd5e1; }
.bridge-row { padding: 5px 8px; background: #0b0e17; border: 1px solid #1e293b; border-radius: 4px; }
.right-pane { display: flex; flex-direction: column; overflow: hidden; background: #0a0d14; }
.tab-bar { display: flex; gap: 6px; padding: 8px 14px; background: #0f1523; border-bottom: 1px solid #1e293b; }
.tab-btn { padding: 6px 12px; font-size: 12px; font-family: monospace; background: #111827; border: 1px solid #334155; color: #94a3b8; border-radius: 5px; cursor: pointer; }
.tab-btn.active { background: #1e293b; border-color: #f59e0b; color: #fbbf24; font-weight: bold; }
.tab-panel { flex: 1; display: none; overflow: hidden; }
.tab-panel.active { display: flex; flex-direction: column; }
.files-split { flex: 1; display: flex; overflow: hidden; }
.sidebar { width: 250px; background: #0f141f; border-right: 1px solid #1e293b; display: flex; flex-direction: column; padding: 8px; overflow: hidden; }
.sidebar input { width: 100%; padding: 6px 8px; margin-bottom: 8px; background: #090d16; border: 1px solid #334155; border-radius: 4px; color: #e2e8f0; font-size: 11px; font-family: monospace; }
#fileList { flex: 1; overflow-y: auto; }
.sidebar button { display: block; width: 100%; text-align: left; padding: 6px 8px; margin-bottom: 3px; background: transparent; border: 1px solid transparent; color: #cbd5e1; font-family: monospace; font-size: 11px; border-radius: 4px; cursor: pointer; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sidebar button:hover { background: #1e293b; }
.sidebar button.active { background: #1e293b; border-color: #f59e0b; color: #fbbf24; }
.file-viewer { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.file-header { padding: 8px 14px; background: #0f1523; border-bottom: 1px solid #1e293b; font-size: 12px; color: #fbbf24; }
.content-scroll { flex: 1; overflow-y: auto; padding: 16px; }
pre { font-size: 11.5px; line-height: 1.55; white-space: pre-wrap; color: #e2e8f0; }
.claim-badge { display: inline-block; padding: 1px 6px; margin: 0 2px; border-radius: 3px; background: rgba(245, 158, 11, 0.2); border: 1px solid #f59e0b; color: #fbbf24; font-family: monospace; font-size: 10.5px; font-weight: bold; cursor: pointer; }
.claim-badge:hover { background: #f59e0b; color: #090d16; }
.claim-drawer { border-top: 2px solid #f59e0b; background: #0f172a; max-height: 230px; overflow-y: auto; font-size: 11px; }
.claim-drawer.hidden { display: none; }
.claim-drawer-head { display: flex; justify-content: space-between; align-items: center; padding: 6px 12px; background: #1e293b; color: #fbbf24; font-weight: bold; }
.claim-drawer-head button { padding: 2px 8px; background: #0f172a; border: 1px solid #475569; color: #e2e8f0; border-radius: 3px; cursor: pointer; font-size: 10.5px; }
.claim-drawer-body { padding: 10px 12px; line-height: 1.5; }
.claim-snippet { margin-top: 6px; padding: 8px; background: #080b12; border: 1px solid #334155; border-radius: 4px; white-space: pre-wrap; color: #a7f3d0; font-family: monospace; font-size: 11px; }
.panel-scroll { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 10px; }
.card { background: #0f1523; border: 1px solid #1e293b; border-radius: 6px; padding: 12px; font-size: 12px; }
.diff-cols { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 8px; }
.diff-box { background: #090d16; border: 1px solid #334155; border-radius: 4px; padding: 8px; font-size: 11px; line-height: 1.45; }
.verdict { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold; background: #1e293b; color: #fbbf24; margin-left: 6px; }
@media (max-width: 900px) { .workbench { grid-template-columns: 1fr; grid-template-rows: 45vh 1fr; } .left-pane { border-right: none; border-bottom: 1px solid #1e293b; } }`;
}

export function buildWorkbenchJs(): string {
  return `// Sovereign Offline 160-Agent Forensic Workbench (Zero CORS / file:// compatible)
document.addEventListener('DOMContentLoaded', () => {
  const data = window.__DOSSIER_WORKBENCH__;
  if (!data) {
    document.getElementById('contentArea').textContent = 'Missing workbench_data.js bundle.';
    return;
  }

  // Render Top Badges
  const badgesEl = document.getElementById('statsBadges');
  const badgeItems = [
    'Nodes: ' + data.graphNodes.length,
    'Edges: ' + data.graphEdges.length,
    'Modularity Q: ' + data.meta.modularityQ,
    'Max k-Core: ' + data.meta.maxKCore,
    'Claims Indexed: ' + Object.keys(data.claimsIndex || {}).length
  ];
  if (data.meta.ipfsCidV1) {
    badgeItems.push('IPFS: ' + data.meta.ipfsCidV1.slice(0, 14) + '...');
  }
  if (data.meta.bitcoinBlockHeight) {
    badgeItems.push('BTC Tip: #' + data.meta.bitcoinBlockHeight);
  }
  badgeItems.forEach((txt) => {
    const span = document.createElement('span');
    span.className = 'badge';
    span.textContent = txt;
    badgesEl.appendChild(span);
  });

  // Tab switching
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
  });

  // File Browser, Content Viewer & Interactive [CLM-*] Byte-Offset / JSON Pointer Inspector
  const fileListEl = document.getElementById('fileList');
  const fileFilterEl = document.getElementById('fileFilter');
  const currentFileNameEl = document.getElementById('currentFileName');
  const contentAreaEl = document.getElementById('contentArea');
  const claimDrawer = document.getElementById('claimDrawer');
  const claimDrawerTitle = document.getElementById('claimDrawerTitle');
  const claimDrawerBody = document.getElementById('claimDrawerBody');
  document.getElementById('closeClaimDrawer').addEventListener('click', () => {
    claimDrawer.classList.add('hidden');
  });

  function resolvePointer(obj, pointer) {
    if (!pointer || pointer === '/') return obj;
    const parts = pointer.slice(1).split('/').map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'));
    let cur = obj;
    for (const seg of parts) {
      if (cur && typeof cur === 'object' && seg in cur) cur = cur[seg];
      else return undefined;
    }
    return cur;
  }

  function inspectClaim(claimId) {
    const c = (data.claimsIndex || {})[claimId];
    if (!c) return;
    const rawContent = data.filesMap[c.source_path] || '';
    let resolvedSnippet = rawContent.slice(c.byte_offset_start, c.byte_offset_end);
    let pointerValue = null;
    if (c.json_pointer && rawContent) {
      try {
        const parsed = JSON.parse(rawContent);
        const val = resolvePointer(parsed, c.json_pointer);
        if (val !== undefined) pointerValue = typeof val === 'string' ? val : JSON.stringify(val, null, 2);
      } catch {}
    }
    claimDrawerTitle.textContent = 'Evidence Inspector: ' + c.claim_id + ' (Tier ' + c.truth_tier + ')';
    claimDrawerBody.innerHTML =
      '<div><strong>Source Artifact:</strong> ' + escapeHtml(c.source_path) + '</div>' +
      '<div><strong>SHA-256:</strong> <code>' + escapeHtml(c.source_sha256) + '</code></div>' +
      '<div><strong>Byte Range:</strong> ' + c.byte_offset_start + '..' + c.byte_offset_end +
        (c.json_pointer ? ' | <strong>RFC 6901 JSON Pointer:</strong> <code>' + escapeHtml(c.json_pointer) + '</code>' : '') + '</div>' +
      '<div class="claim-snippet">' + escapeHtml(pointerValue || resolvedSnippet || 'Source excerpt empty') + '</div>' +
      '<div style="margin-top:6px"><button type="button" id="openSourceBtn" style="padding:3px 8px;background:#f59e0b;border:none;border-radius:3px;color:#080b12;font-weight:bold;cursor:pointer;">Jump to Source Evidence File</button></div>';
    claimDrawer.classList.remove('hidden');
    const jumpBtn = document.getElementById('openSourceBtn');
    if (jumpBtn) jumpBtn.onclick = () => openFile(c.source_path);
  }

  function openFile(name) {
    currentFileNameEl.textContent = name;
    const raw = data.filesMap[name] || 'File content unavailable.';
    const escaped = escapeHtml(raw);
    const linked = escaped.replace(/\\b(CLM-[A-Za-z0-9_-]+)\\b/g, (m) => {
      if ((data.claimsIndex || {})[m]) {
        return '<button type="button" class="claim-badge" data-claim="' + m + '">' + m + '</button>';
      }
      return m;
    });
    contentAreaEl.innerHTML = linked;
    contentAreaEl.querySelectorAll('.claim-badge').forEach((btn) => {
      btn.addEventListener('click', () => inspectClaim(btn.dataset.claim));
    });
    document.querySelectorAll('#fileList button').forEach((b) => {
      b.classList.toggle('active', b.dataset.file === name);
    });
  }

  function renderFileList(q) {
    fileListEl.innerHTML = '';
    const query = (q || '').toLowerCase();
    data.fileList
      .filter((f) => !query || f.toLowerCase().includes(query))
      .forEach((f) => {
        const btn = document.createElement('button');
        btn.textContent = f;
        btn.dataset.file = f;
        if (f === currentFileNameEl.textContent) btn.classList.add('active');
        btn.onclick = () => openFile(f);
        fileListEl.appendChild(btn);
      });
  }

  fileFilterEl.addEventListener('input', (e) => renderFileList(e.target.value));
  renderFileList('');
  openFile(data.fileList[0] || '00_EXEC_SUMMARY.md');

  // Synchronized Timeline
  const timelineEl = document.getElementById('timelineContainer');
  if (data.timelineRows.length === 0) {
    timelineEl.innerHTML = '<div class="card">No milestone records available.</div>';
  } else {
    data.timelineRows.forEach((row) => {
      const card = document.createElement('div');
      card.className = 'card';
      card.innerHTML = '<div><strong style="color:#f59e0b">' + escapeHtml(row.period) + '</strong> · ' + escapeHtml(row.phase) + '</div>' +
        '<div style="margin-top:4px;color:#e2e8f0">' + escapeHtml(row.milestone) + '</div>' +
        '<div style="margin-top:4px;font-size:11px;color:#94a3b8">Impact: ' + escapeHtml(row.impact) + ' | Source: ' + escapeHtml(row.source) + '</div>';
      timelineEl.appendChild(card);
    });
  }

  // Bayesian Log-Odds Contradiction Diff & Tribunal
  const tribunalEl = document.getElementById('tribunalContainer');
  if (data.contradictions.length === 0) {
    tribunalEl.innerHTML = '<div class="card">Zero material discrepancies escalated by Stage-3 Tribunal.</div>';
  } else {
    data.contradictions.forEach((entry) => {
      const card = document.createElement('div');
      card.className = 'card';
      const posterior = entry.bayesian_posterior !== undefined ? entry.bayesian_posterior : entry.corroboration_score;
      const lrs = Array.isArray(entry.likelihood_ratios_applied) ? entry.likelihood_ratios_applied.join(' × ') : 'N/A';
      card.innerHTML =
        '<div><strong>' + escapeHtml(entry.id) + ': ' + escapeHtml(entry.claim_area) + '</strong>' +
        '<span class="verdict">' + escapeHtml(entry.judge_verdict) + ' (Tier ' + entry.evidence_tier + ' | P(H|E)=' + posterior + ')</span></div>' +
        '<div class="diff-cols">' +
          '<div class="diff-box"><strong style="color:#38bdf8">Prosecutor Charge</strong><div style="margin-top:4px">' + escapeHtml(entry.prosecutor_charge) + '</div></div>' +
          '<div class="diff-box"><strong style="color:#34d399">Defense Red-Team Rebuttal</strong><div style="margin-top:4px">' + escapeHtml(entry.defense_rebuttal) + '</div></div>' +
        '</div>' +
        '<div style="margin-top:6px;font-size:11px;color:#94a3b8">Prior: ' + (entry.prior_probability ?? 0.35) + ' | LRs: [' + lrs + '] | Dest: ' + escapeHtml(entry.destination_file) + '</div>';
      tribunalEl.appendChild(card);
    });
  }

  // Shortest-Path Hidden Bridges & Centrality Panel
  const bridgesEl = document.getElementById('bridgesContent');
  data.topCentralNodes.slice(0, 4).forEach((cn) => {
    const div = document.createElement('div');
    div.className = 'bridge-row';
    div.textContent = '[Centrality ' + cn.betweennessCentrality + ' | k=' + cn.kCore + '] ' + cn.label + ' (' + cn.nodeType + ')';
    bridgesEl.appendChild(div);
  });
  data.hiddenBridges.slice(0, 4).forEach((b) => {
    const div = document.createElement('div');
    div.className = 'bridge-row';
    div.textContent = '[Bridge ' + b.hops + '-hop] ' + b.pathLabels.join(' -> ');
    bridgesEl.appendChild(div);
  });

  // Multi-Hop BFS Collusion Path Finder Controls
  const fromSelect = document.getElementById('pathFromSelect');
  const toSelect = document.getElementById('pathToSelect');
  const pathResultBanner = document.getElementById('pathResultBanner');
  let highlightedNodeIds = new Set();
  let highlightedEdgeKeys = new Set();

  data.graphNodes.forEach((n, idx) => {
    const opt1 = document.createElement('option');
    opt1.value = n.id;
    opt1.textContent = n.label.slice(0, 34);
    fromSelect.appendChild(opt1);
    const opt2 = document.createElement('option');
    opt2.value = n.id;
    opt2.textContent = n.label.slice(0, 34);
    if (idx === Math.min(data.graphNodes.length - 1, 3)) opt2.selected = true;
    toSelect.appendChild(opt2);
  });

  function runCollusionPathBfs() {
    const startId = fromSelect.value;
    const endId = toSelect.value;
    highlightedNodeIds = new Set();
    highlightedEdgeKeys = new Set();
    if (!startId || !endId || startId === endId) {
      pathResultBanner.textContent = 'Select two distinct nodes to trace a shortest collusion path.';
      pathResultBanner.classList.remove('hidden');
      return;
    }
    const adj = new Map();
    data.graphNodes.forEach((n) => adj.set(n.id, []));
    data.graphEdges.forEach((e) => {
      if (adj.has(e.source)) adj.get(e.source).push({ next: e.target, rel: e.relationship });
      if (adj.has(e.target)) adj.get(e.target).push({ next: e.source, rel: e.relationship });
    });

    const visited = new Set([startId]);
    const parent = new Map();
    const queue = [startId];
    let found = false;
    while (queue.length > 0 && !found) {
      const cur = queue.shift();
      for (const step of adj.get(cur) || []) {
        if (!visited.has(step.next)) {
          visited.add(step.next);
          parent.set(step.next, { id: cur, rel: step.rel });
          if (step.next === endId) { found = true; break; }
          queue.push(step.next);
        }
      }
    }

    if (!found) {
      pathResultBanner.textContent = 'No undirected graph path exists between selected nodes.';
      pathResultBanner.classList.remove('hidden');
      return;
    }

    const nodeById = new Map(data.graphNodes.map((n) => [n.id, n]));
    const chain = [];
    const rels = [];
    let cur = endId;
    while (cur) {
      chain.unshift(cur);
      highlightedNodeIds.add(cur);
      const p = parent.get(cur);
      if (p) {
        rels.unshift(p.rel);
        highlightedEdgeKeys.add(cur + '|' + p.id);
        highlightedEdgeKeys.add(p.id + '|' + cur);
        cur = p.id;
      } else {
        cur = null;
      }
    }
    const chainText = chain.map((id, i) => (nodeById.get(id)?.label || id) + (rels[i] ? ' --[' + rels[i] + ']--> ' : '')).join('');
    pathResultBanner.textContent = 'Shortest Path (' + (chain.length - 1) + ' hops): ' + chainText;
    pathResultBanner.classList.remove('hidden');
  }

  document.getElementById('tracePathBtn').addEventListener('click', runCollusionPathBfs);
  document.getElementById('clearPathBtn').addEventListener('click', () => {
    highlightedNodeIds = new Set();
    highlightedEdgeKeys = new Set();
    pathResultBanner.classList.add('hidden');
  });

  // Canvas Force-Directed Graph with Layer Toggles + Neon Red Shortest Path Overlay
  const canvas = document.getElementById('graphCanvas');
  const ctx = canvas.getContext('2d');
  const tooltip = document.getElementById('nodeTooltip');
  let activeLayer = 'all';

  const typeColors = {
    'Entity': '#f59e0b',
    'Person': '#38bdf8',
    'Subsidiary': '#10b981',
    'Contract/Docket': '#f43f5e',
    'ASN/IP_Block': '#a855f7',
    'Swarm_Cluster': '#eab308',
    'Public_Claim': '#94a3b8'
  };

  let simNodes = [];
  let simEdges = [];

  function initGraphLayout(layer) {
    activeLayer = layer;
    const width = canvas.parentElement.clientWidth || 600;
    const height = canvas.parentElement.clientHeight || 420;
    canvas.width = width;
    canvas.height = height;

    const filteredEdges = layer === 'all'
      ? data.graphEdges
      : data.graphEdges.filter((e) => e.layer === layer || e.layer === 'core');
    const keepIds = new Set();
    filteredEdges.forEach((e) => { keepIds.add(e.source); keepIds.add(e.target); });
    const nodes = data.graphNodes.filter((n) => layer === 'all' || keepIds.has(n.id) || n.layer === 'core');

    simNodes = nodes.map((n, i) => {
      const angle = (i / Math.max(1, nodes.length)) * Math.PI * 2;
      const radius = i === 0 ? 0 : Math.min(width, height) * 0.32;
      return {
        ...n,
        x: width / 2 + Math.cos(angle) * radius,
        y: height / 2 + Math.sin(angle) * radius,
        vx: 0,
        vy: 0
      };
    });
    simEdges = filteredEdges;
  }

  document.querySelectorAll('#layerToggles button').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#layerToggles button').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      initGraphLayout(btn.dataset.layer);
    });
  });

  function stepPhysics() {
    const width = canvas.width;
    const height = canvas.height;
    const byId = new Map(simNodes.map((n) => [n.id, n]));

    for (let i = 0; i < simNodes.length; i++) {
      const a = simNodes[i];
      a.vx += (width / 2 - a.x) * 0.002;
      a.vy += (height / 2 - a.y) * 0.002;
      for (let j = i + 1; j < simNodes.length; j++) {
        const b = simNodes[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const d2 = dx * dx + dy * dy + 1;
        const rep = 950 / d2;
        a.vx += dx * rep;
        a.vy += dy * rep;
        b.vx -= dx * rep;
        b.vy -= dy * rep;
      }
    }

    for (const e of simEdges) {
      const s = byId.get(e.source);
      const t = byId.get(e.target);
      if (!s || !t) continue;
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const diff = (dist - 105) * 0.015;
      s.vx += (dx / dist) * diff;
      s.vy += (dy / dist) * diff;
      t.vx -= (dx / dist) * diff;
      t.vy -= (dy / dist) * diff;
    }

    for (const n of simNodes) {
      n.vx *= 0.85;
      n.vy *= 0.85;
      n.x = Math.max(24, Math.min(width - 24, n.x + n.vx));
      n.y = Math.max(24, Math.min(height - 24, n.y + n.vy));
    }
  }

  function drawGraph() {
    stepPhysics();
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const byId = new Map(simNodes.map((n) => [n.id, n]));

    for (const e of simEdges) {
      const s = byId.get(e.source);
      const t = byId.get(e.target);
      if (!s || !t) continue;
      const isHot = highlightedEdgeKeys.has(e.source + '|' + e.target);
      ctx.lineWidth = isHot ? 3 : 1;
      ctx.strokeStyle = isHot ? '#ff1e56' : 'rgba(148, 163, 184, 0.35)';
      ctx.beginPath();
      ctx.moveTo(s.x, s.y);
      ctx.lineTo(t.x, t.y);
      ctx.stroke();
    }

    ctx.font = '10px monospace';
    for (const n of simNodes) {
      const r = 5 + Math.min(8, n.degree);
      const isNodeHot = highlightedNodeIds.has(n.id);
      if (isNodeHot) {
        ctx.strokeStyle = '#ff1e56';
        ctx.lineWidth = 2.5;
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 4, 0, Math.PI * 2);
        ctx.stroke();
      }
      ctx.fillStyle = isNodeHot ? '#ff1e56' : (typeColors[n.nodeType] || '#94a3b8');
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = isNodeHot ? '#fecdd3' : '#e2e8f0';
      ctx.fillText(n.label.slice(0, 22), n.x + r + 4, n.y + 3);
    }

    requestAnimationFrame(drawGraph);
  }

  canvas.addEventListener('click', (ev) => {
    const rect = canvas.getBoundingClientRect();
    const x = ev.clientX - rect.left;
    const y = ev.clientY - rect.top;
    const hit = simNodes.find((n) => Math.hypot(n.x - x, n.y - y) <= 14);
    if (hit) {
      tooltip.classList.remove('hidden');
      tooltip.innerHTML =
        '<strong style="color:#fbbf24">' + escapeHtml(hit.label) + '</strong> [' + escapeHtml(hit.nodeType) + ']<br>' +
        'Layer: ' + escapeHtml(hit.layer) + ' · Degree: ' + hit.degree + ' · Betweenness: ' + hit.betweennessCentrality + ' · k-Core: ' + hit.kCore + ' · Comm #' + hit.communityId;
    } else {
      tooltip.classList.add('hidden');
    }
  });

  window.addEventListener('resize', () => initGraphLayout(activeLayer));
  initGraphLayout('all');
  drawGraph();

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
});`;
}

