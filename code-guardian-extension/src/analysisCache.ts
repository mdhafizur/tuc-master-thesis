import { SecurityIssue } from './analyzer';
import * as crypto from 'crypto';

/**
 * Cache entry for analysis results
 */
interface CacheEntry {
	hash: string;
	result: SecurityIssue[];
	timestamp: number;
	model: string;
	ragEnabled: boolean;
}

/**
 * LRU Cache configuration
 */
const CACHE_CONFIG = {
	maxSize: 100,           // Maximum number of entries
	maxAge: 1000 * 60 * 30, // 30 minutes
	cleanupInterval: 1000 * 60 * 5 // Clean every 5 minutes
};

/**
 * Analysis Result Cache with LRU eviction
 *
 * Caches analysis results based on code hash to avoid redundant LLM calls
 * for unchanged code. Implements LRU (Least Recently Used) eviction strategy.
 */
export class AnalysisCache {
	private cache: Map<string, CacheEntry>;
	private accessOrder: string[]; // Track access order for LRU
	private cleanupTimer: NodeJS.Timeout | null = null;
	private stats = {
		hits: 0,
		misses: 0,
		evictions: 0
	};

	constructor() {
		this.cache = new Map();
		this.accessOrder = [];
		this.startCleanupTimer();
	}

	/**
	 * Generate hash for code + model + prompt mode combination
	 */
	private generateHash(code: string, model: string, ragEnabled: boolean = false): string {
		const mode = ragEnabled ? 'rag-on' : 'rag-off';
		return crypto
			.createHash('sha256')
			.update(`${code}:${model}:${mode}`)
			.digest('hex')
			.substring(0, 16); // Use first 16 chars for efficiency
	}

	/**
	 * Update access order for LRU
	 */
	private updateAccessOrder(hash: string): void {
		// Remove from current position
		const index = this.accessOrder.indexOf(hash);
		if (index > -1) {
			this.accessOrder.splice(index, 1);
		}
		// Add to end (most recently used)
		this.accessOrder.push(hash);
	}

	/**
	 * Evict least recently used entry if cache is full
	 */
	private evictIfNeeded(): void {
		if (this.cache.size >= CACHE_CONFIG.maxSize) {
			// Remove least recently used (first in array)
			const lruHash = this.accessOrder.shift();
			if (lruHash) {
				this.cache.delete(lruHash);
				this.stats.evictions++;
			}
		}
	}

	/**
	 * Get cached analysis result
	 */
	get(code: string, model: string, ragEnabled: boolean = false): SecurityIssue[] | null {
		const hash = this.generateHash(code, model, ragEnabled);
		const entry = this.cache.get(hash);

		if (!entry) {
			this.stats.misses++;
			return null;
		}

		// Check if entry is expired
		const age = Date.now() - entry.timestamp;
		if (age > CACHE_CONFIG.maxAge) {
			this.cache.delete(hash);
			const index = this.accessOrder.indexOf(hash);
			if (index > -1) {
				this.accessOrder.splice(index, 1);
			}
			this.stats.misses++;
			return null;
		}

		// Update access order and return cached result
		this.updateAccessOrder(hash);
		this.stats.hits++;
		return entry.result;
	}

	/**
	 * Set analysis result in cache
	 */
	set(code: string, model: string, result: SecurityIssue[], ragEnabled: boolean = false): void {
		const hash = this.generateHash(code, model, ragEnabled);

		// Evict if needed before adding new entry
		this.evictIfNeeded();

		this.cache.set(hash, {
			hash,
			result,
			timestamp: Date.now(),
			model,
			ragEnabled
		});

		this.updateAccessOrder(hash);
	}

	/**
	 * Check if code is in cache
	 */
	has(code: string, model: string, ragEnabled: boolean = false): boolean {
		const hash = this.generateHash(code, model, ragEnabled);
		const entry = this.cache.get(hash);

		if (!entry) {
			return false;
		}

		// Check expiration
		const age = Date.now() - entry.timestamp;
		return age <= CACHE_CONFIG.maxAge;
	}

	/**
	 * Clear all cached entries
	 */
	clear(): void {
		this.cache.clear();
		this.accessOrder = [];
		this.stats = { hits: 0, misses: 0, evictions: 0 };
	}

	/**
	 * Clear expired entries
	 */
	private clearExpired(): void {
		const now = Date.now();
		const expiredHashes: string[] = [];

		for (const [hash, entry] of this.cache.entries()) {
			const age = now - entry.timestamp;
			if (age > CACHE_CONFIG.maxAge) {
				expiredHashes.push(hash);
			}
		}

		expiredHashes.forEach(hash => {
			this.cache.delete(hash);
			const index = this.accessOrder.indexOf(hash);
			if (index > -1) {
				this.accessOrder.splice(index, 1);
			}
		});
	}

	/**
	 * Start periodic cleanup of expired entries
	 */
	private startCleanupTimer(): void {
		this.cleanupTimer = setInterval(() => {
			this.clearExpired();
		}, CACHE_CONFIG.cleanupInterval);
	}

	/**
	 * Stop cleanup timer
	 */
	dispose(): void {
		if (this.cleanupTimer) {
			clearInterval(this.cleanupTimer);
			this.cleanupTimer = null;
		}
	}

	/**
	 * Get cache statistics
	 */
	getStats() {
		const hitRate = this.stats.hits + this.stats.misses > 0
			? (this.stats.hits / (this.stats.hits + this.stats.misses) * 100).toFixed(2)
			: '0.00';

		return {
			size: this.cache.size,
			maxSize: CACHE_CONFIG.maxSize,
			hits: this.stats.hits,
			misses: this.stats.misses,
			evictions: this.stats.evictions,
			hitRate: `${hitRate}%`,
			utilizationRate: `${((this.cache.size / CACHE_CONFIG.maxSize) * 100).toFixed(2)}%`
		};
	}

	/**
	 * Reset statistics
	 */
	resetStats(): void {
		this.stats = { hits: 0, misses: 0, evictions: 0 };
	}

	/**
	 * Get cache size
	 */
	get size(): number {
		return this.cache.size;
	}
}

// Singleton instance
let cacheInstance: AnalysisCache | null = null;

/**
 * Get or create cache instance
 */
export function getAnalysisCache(): AnalysisCache {
	if (!cacheInstance) {
		cacheInstance = new AnalysisCache();
	}
	return cacheInstance;
}

/**
 * Dispose cache instance
 */
export function disposeAnalysisCache(): void {
	if (cacheInstance) {
		cacheInstance.dispose();
		cacheInstance = null;
	}
}
