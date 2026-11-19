export interface YearlyFinancials {
  fiscalYear: number;
  revenue: number;
  receivables: number;
  cogs: number;
  currentAssets: number;
  ppe: number;
  depreciation: number;
  totalAssets: number;
  sgaExpense: number;
  netIncome: number;
  operatingCashFlow: number;
  currentLiabilities: number;
  longTermDebt: number;
  retainedEarnings?: number;
  ebit?: number;
  stockholdersEquity?: number;
}

export interface AccountingForensicsResult {
  status: 'COMPUTED' | 'INSUFFICIENT_DATA';
  currentYear: number | null;
  priorYear: number | null;
  beneishMScore: number | null;
  manipulationProbabilityFlag: 'HIGH_RISK' | 'LOW_RISK' | 'UNAVAILABLE';
  altmanZScore: number | null;
  altmanZone: 'SAFE' | 'GREY_ZONE' | 'DISTRESS' | 'UNAVAILABLE';
  sloanAccrualRatio: number | null;
  secondDigitBenford: {
    sampleSize: number;
    chiSquare: number | null;
    mad: number | null;
    roundingAnomalyDetected: boolean;
  };
  componentRatios?: Record<string, number>;
  summaryVerdict: string;
}

export function computeAccountingForensics(
  current: YearlyFinancials | null,
  prior: YearlyFinancials | null,
  rawNumericDisclosures: number[]
): AccountingForensicsResult {
  // 1. Second-Digit Benford's Law (Detects human threshold rounding, e.g., $9,900)
  const validNums = rawNumericDisclosures
    .map((n) => Math.abs(Math.trunc(Number(n))))
    .filter((n) => Number.isFinite(n) && n >= 10);

  const N = validNums.length;
  let chiSquare: number | null = null;
  let mad: number | null = null;
  let roundingAnomalyDetected = false;

  if (N >= 50) {
    // Theoretical 2nd-digit Benford probabilities for d2 in 0..9
    const expectedProb = [
      0.11968, 0.11389, 0.10882, 0.10433, 0.10031,
      0.09668, 0.09337, 0.09035, 0.08757, 0.08500,
    ];
    const counts = new Array(10).fill(0);
    for (const num of validNums) {
      const s = num.toString();
      const d2 = parseInt(s[1], 10);
      if (d2 >= 0 && d2 <= 9) counts[d2]++;
    }

    chiSquare = 0;
    let absDiffSum = 0;
    for (let d = 0; d < 10; d++) {
      const obsProp = counts[d] / N;
      const expCount = expectedProb[d] * N;
      chiSquare += Math.pow(counts[d] - expCount, 2) / expCount;
      absDiffSum += Math.abs(obsProp - expectedProb[d]);
    }
    chiSquare = Number(chiSquare.toFixed(3));
    mad = Number((absDiffSum / 10).toFixed(4));
    // Critical value for df=9 at alpha=0.01 is 21.666; MAD > 0.012 indicates non-conformity
    roundingAnomalyDetected = chiSquare > 21.666 && mad > 0.012;
  }

  // 2. Beneish M-Score & Sloan Accrual Anomaly (requires 2 consecutive fiscal years)
  if (!current || !prior || prior.revenue <= 0 || current.revenue <= 0 || current.totalAssets <= 0 || prior.totalAssets <= 0) {
    return {
      status: 'INSUFFICIENT_DATA',
      currentYear: current?.fiscalYear ?? null,
      priorYear: prior?.fiscalYear ?? null,
      beneishMScore: null,
      manipulationProbabilityFlag: 'UNAVAILABLE',
      altmanZScore: null,
      altmanZone: 'UNAVAILABLE',
      sloanAccrualRatio: null,
      secondDigitBenford: { sampleSize: N, chiSquare, mad, roundingAnomalyDetected },
      summaryVerdict:
        N >= 50
          ? `INSUFFICIENT_GAAP_HISTORY for Beneish M-Score; 2nd-Digit Benford tested across N=${N} disclosures (Chi2=${chiSquare}, MAD=${mad}, RoundingAnomaly=${roundingAnomalyDetected}).`
          : `INSUFFICIENT_DATA (Need 2 consecutive audited annual SEC XBRL statements for Beneish M-Score; 2nd-Digit Benford sample N=${N} < 50).`,
    };
  }

  const safeDiv = (a: number, b: number, fallback = 1) => (b === 0 ? fallback : a / b);

  // Days Sales in Receivables Index (DSRI)
  const dsri = safeDiv(
    safeDiv(current.receivables, current.revenue, 0),
    safeDiv(prior.receivables, prior.revenue, 0),
    1
  );

  // Gross Margin Index (GMI)
  const priorGM = safeDiv(prior.revenue - prior.cogs, prior.revenue, 0.25);
  const currGM = safeDiv(current.revenue - current.cogs, current.revenue, 0.25);
  const gmi = safeDiv(priorGM, currGM, 1);

  // Asset Quality Index (AQI)
  const currAQ = 1 - safeDiv(current.currentAssets + current.ppe, current.totalAssets, 1);
  const priorAQ = 1 - safeDiv(prior.currentAssets + prior.ppe, prior.totalAssets, 1);
  const aqi = Math.max(0.2, Math.min(5, safeDiv(currAQ, priorAQ, 1)));

  // Sales Growth Index (SGI)
  const sgi = safeDiv(current.revenue, prior.revenue, 1);

  // Depreciation Index (DEPI)
  const priorDepRate = safeDiv(prior.depreciation, prior.depreciation + prior.ppe, 0.1);
  const currDepRate = safeDiv(current.depreciation, current.depreciation + current.ppe, 0.1);
  const depi = Math.max(0.2, Math.min(5, safeDiv(priorDepRate, currDepRate, 1)));

  // SG&A Expenses Index (SGAI)
  const priorSgaRatio = safeDiv(prior.sgaExpense, prior.revenue, 0.1);
  const currSgaRatio = safeDiv(current.sgaExpense, current.revenue, 0.1);
  const sgai = safeDiv(currSgaRatio, priorSgaRatio, 1);

  // Leverage Index (LVGI)
  const currLev = safeDiv(current.currentLiabilities + current.longTermDebt, current.totalAssets, 0.3);
  const priorLev = safeDiv(prior.currentLiabilities + prior.longTermDebt, prior.totalAssets, 0.3);
  const lvgi = safeDiv(currLev, priorLev, 1);

  // Total Accruals to Total Assets (TATA / Sloan Accrual Ratio)
  const tata = safeDiv(current.netIncome - current.operatingCashFlow, current.totalAssets, 0);

  const mScore =
    -4.84 +
    0.92 * dsri +
    0.528 * gmi +
    0.404 * aqi +
    0.892 * sgi +
    0.115 * depi -
    0.172 * sgai +
    4.679 * tata -
    0.327 * lvgi;

  // Altman Z''-Score (General/Non-Manufacturing adaptation for book equity when market cap isn't joined)
  let altmanZScore: number | null = null;
  let altmanZone: AccountingForensicsResult['altmanZone'] = 'UNAVAILABLE';
  const totalLiabilities = current.currentLiabilities + current.longTermDebt;
  if (current.totalAssets > 0 && totalLiabilities > 0 && typeof current.stockholdersEquity === 'number') {
    const workingCapital = current.currentAssets - current.currentLiabilities;
    const x1 = workingCapital / current.totalAssets;
    const x2 = (current.retainedEarnings ?? current.netIncome) / current.totalAssets;
    const x3 = (current.ebit ?? current.netIncome) / current.totalAssets;
    const x4 = current.stockholdersEquity / totalLiabilities;
    const x5 = current.revenue / current.totalAssets;
    const z = 1.2 * x1 + 1.4 * x2 + 3.3 * x3 + 0.6 * x4 + 1.0 * x5;
    altmanZScore = Number(z.toFixed(3));
    altmanZone = z > 2.99 ? 'SAFE' : z >= 1.81 ? 'GREY_ZONE' : 'DISTRESS';
  }

  const mFixed = Number(mScore.toFixed(4));
  const flag: AccountingForensicsResult['manipulationProbabilityFlag'] = mFixed > -1.78 ? 'HIGH_RISK' : 'LOW_RISK';
  const tataFixed = Number(tata.toFixed(4));

  const summaryVerdict =
    `COMPUTED FY${prior.fiscalYear}->FY${current.fiscalYear}: Beneish M-Score=${mFixed} (${flag}; threshold -1.78), ` +
    `Sloan Accrual TATA=${tataFixed}, Altman Z=${altmanZScore ?? 'N/A'} (${altmanZone}), ` +
    `2nd-Digit Benford (N=${N >= 50 ? N : `${N} < 50`}, RoundingAnomaly=${roundingAnomalyDetected}).`;

  return {
    status: 'COMPUTED',
    currentYear: current.fiscalYear,
    priorYear: prior.fiscalYear,
    beneishMScore: mFixed,
    manipulationProbabilityFlag: flag,
    altmanZScore,
    altmanZone,
    sloanAccrualRatio: tataFixed,
    secondDigitBenford: { sampleSize: N, chiSquare, mad, roundingAnomalyDetected },
    componentRatios: {
      dsri: Number(dsri.toFixed(4)),
      gmi: Number(gmi.toFixed(4)),
      aqi: Number(aqi.toFixed(4)),
      sgi: Number(sgi.toFixed(4)),
      depi: Number(depi.toFixed(4)),
      sgai: Number(sgai.toFixed(4)),
      lvgi: Number(lvgi.toFixed(4)),
      tata: tataFixed,
    },
    summaryVerdict,
  };
}

export function extractAnnualFinancialsFromGaap(
  gaap: Record<string, any> | undefined
): { current: YearlyFinancials | null; prior: YearlyFinancials | null } {
  if (!gaap || typeof gaap !== 'object') return { current: null, prior: null };

  const getAnnualMap = (tags: string[]): Map<number, number> => {
    const out = new Map<number, number>();
    const bestScore = new Map<number, { tagIdx: number; frameRank: number; filedMs: number; endMs: number }>();

    const isBetter = (
      cand: { tagIdx: number; frameRank: number; filedMs: number; endMs: number },
      prev?: { tagIdx: number; frameRank: number; filedMs: number; endMs: number }
    ) => {
      if (!prev) return true;
      if (cand.tagIdx !== prev.tagIdx) return cand.tagIdx < prev.tagIdx;
      if (cand.frameRank !== prev.frameRank) return cand.frameRank > prev.frameRank;
      if (cand.filedMs !== prev.filedMs) return cand.filedMs > prev.filedMs;
      return cand.endMs > prev.endMs;
    };

    for (let tagIdx = 0; tagIdx < tags.length; tagIdx++) {
      const tag = tags[tagIdx];
      const items = gaap[tag]?.units?.USD;
      if (!Array.isArray(items)) continue;
      for (const item of items) {
        if ((item.form === '10-K' || item.form === '20-F' || item.form === '40-F') && typeof item.val === 'number') {
          const endYear = Number(String(item.end || '').slice(0, 4)) || Number(item.fy || 0);
          if (endYear < 2000) continue;
          const endMs = item.end ? Date.parse(String(item.end)) || 0 : 0;
          if (item.start && item.end) {
            const days = (endMs - Date.parse(String(item.start))) / 86_400_000;
            if (Number.isFinite(days) && days < 250) continue;
          }
          const frame = String(item.frame || '').trim().toUpperCase();
          const frameRank =
            frame === `CY${endYear}` || frame === `CY${endYear}I`
              ? 3
              : !frame || frame.startsWith(`CY${endYear}`)
                ? 2
                : 1;
          const filedMs = item.filed ? Date.parse(String(item.filed)) || 0 : 0;
          const cand = { tagIdx, frameRank, filedMs, endMs };
          if (isBetter(cand, bestScore.get(endYear))) {
            bestScore.set(endYear, cand);
            out.set(endYear, Number(item.val));
          }
        }
      }
    }
    return out;
  };

  const revMap = getAnnualMap([
    'RevenueFromContractWithCustomerExcludingAssessedTax',
    'RevenueFromContractWithCustomerIncludingAssessedTax',
    'Revenues',
    'SalesRevenueNet',
    'SalesRevenueGoodsNet',
    'SalesRevenueServicesNet',
    'InterestAndDividendIncomeOperating',
  ]);
  const assetsMap = getAnnualMap(['Assets']);
  const years = Array.from(revMap.keys())
    .filter((y) => assetsMap.has(y))
    .sort((a, b) => b - a);

  if (years.length < 2) return { current: null, prior: null };

  const yCurr = years[0];
  const yPrior = years[1];

  const recMap = getAnnualMap(['AccountsReceivableNetCurrent', 'ReceivablesNetCurrent', 'AccountsReceivableNet']);
  const cogsMap = getAnnualMap([
    'CostOfGoodsAndServicesSold',
    'CostOfGoodsAndServiceExcludingDepreciationDepletionAndAmortization',
    'CostOfRevenue',
    'CostOfGoodsSold',
  ]);
  const currAssetsMap = getAnnualMap(['AssetsCurrent']);
  const ppeMap = getAnnualMap(['PropertyPlantAndEquipmentNet']);
  const depMap = getAnnualMap(['DepreciationDepletionAndAmortization', 'Depreciation', 'DepreciationAndAmortization']);
  const sgaMap = getAnnualMap(['SellingGeneralAndAdministrativeExpense', 'OperatingExpenses']);
  const niMap = getAnnualMap(['NetIncomeLoss']);
  const ocfMap = getAnnualMap(['NetCashProvidedByUsedInOperatingActivities']);
  const currLiabMap = getAnnualMap(['LiabilitiesCurrent']);
  const ltdMap = getAnnualMap(['LongTermDebtNoncurrent', 'LongTermDebt']);
  const retEarnMap = getAnnualMap(['RetainedEarningsAccumulatedDeficit']);
  const ebitMap = getAnnualMap(['OperatingIncomeLoss']);
  const equityMap = getAnnualMap(['StockholdersEquity']);

  const buildYear = (y: number): YearlyFinancials => ({
    fiscalYear: y,
    revenue: revMap.get(y) || 0,
    receivables: recMap.get(y) || 0,
    cogs: cogsMap.get(y) || 0,
    currentAssets: currAssetsMap.get(y) || 0,
    ppe: ppeMap.get(y) || 0,
    depreciation: depMap.get(y) || 0,
    totalAssets: assetsMap.get(y) || 0,
    sgaExpense: sgaMap.get(y) || 0,
    netIncome: niMap.get(y) || 0,
    operatingCashFlow: ocfMap.get(y) || 0,
    currentLiabilities: currLiabMap.get(y) || 0,
    longTermDebt: ltdMap.get(y) || 0,
    retainedEarnings: retEarnMap.get(y),
    ebit: ebitMap.get(y),
    stockholdersEquity: equityMap.get(y),
  });

  return { current: buildYear(yCurr), prior: buildYear(yPrior) };
}
