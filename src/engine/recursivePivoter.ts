export type PivotEntityType = 'DOMAIN' | 'IP' | 'ASN' | 'PACKAGE';

export interface PivotTask {
  value: string;
  type: PivotEntityType;
  depth: number;
  discoveredFrom: string;
}

export interface PivotEvent {
  task: PivotTask;
  status: 'HIT' | 'EMPTY' | 'ERR';
  latencyMs: number;
  discoveredPivots: PivotTask[];
  payloadSummary: Record<string, unknown>;
  timestampIso: string;
}

/**
 * Autonomous Phase 4+ Recursive Pivot Queue.
 * Bounded by maxDepth and maxTotalProbes to prevent cycles or unbounded fan-out,
 * with bounded concurrency so streaming completes rapidly over NDJSON.
 */
export class AutonomousPivotQueue {
  private visited = new Set<string>();
  private queue: PivotTask[] = [];
  private executedCount = 0;
  private readonly maxDepth: number;
  private readonly maxTotalProbes: number;

  constructor(maxDepth = 2, maxTotalProbes = 24) {
    this.maxDepth = maxDepth;
    this.maxTotalProbes = maxTotalProbes;
  }

  enqueue(task: PivotTask): boolean {
    const normalizedVal = task.value.trim().toLowerCase();
    if (!normalizedVal) return false;
    const key = `${task.type}:${normalizedVal}`;
    if (task.depth > this.maxDepth || this.visited.has(key)) return false;
    this.visited.add(key);
    this.queue.push({ ...task, value: normalizedVal });
    return true;
  }

  public getQueuedCount(): number {
    return this.queue.length;
  }

  public getExecutedCount(): number {
    return this.executedCount;
  }

  async *drain(
    executor: (task: PivotTask) => Promise<{
      status: 'HIT' | 'EMPTY' | 'ERR';
      summary: Record<string, unknown>;
      nextPivots: Array<{ value: string; type: PivotEntityType }>;
    }>,
    batchConcurrency = 4
  ): AsyncGenerator<PivotEvent> {
    while (this.queue.length > 0 && this.executedCount < this.maxTotalProbes) {
      const remaining = this.maxTotalProbes - this.executedCount;
      const batch = this.queue.splice(0, Math.min(batchConcurrency, remaining));
      this.executedCount += batch.length;

      const results = await Promise.all(
        batch.map(async (task): Promise<PivotEvent> => {
          const t0 = performance.now();
          try {
            const res = await executor(task);
            const discoveredPivots: PivotTask[] = [];

            for (const next of res.nextPivots) {
              const child: PivotTask = {
                value: next.value,
                type: next.type,
                depth: task.depth + 1,
                discoveredFrom: `${task.type}:${task.value}`,
              };
              if (this.enqueue(child)) {
                discoveredPivots.push(child);
              }
            }

            return {
              task,
              status: res.status,
              latencyMs: Math.round(performance.now() - t0),
              discoveredPivots,
              payloadSummary: res.summary,
              timestampIso: new Date().toISOString(),
            };
          } catch (err) {
            return {
              task,
              status: 'ERR',
              latencyMs: Math.round(performance.now() - t0),
              discoveredPivots: [],
              payloadSummary: {
                error: err instanceof Error ? err.message : String(err),
              },
              timestampIso: new Date().toISOString(),
            };
          }
        })
      );

      for (const ev of results) {
        yield ev;
      }
    }
  }
}
