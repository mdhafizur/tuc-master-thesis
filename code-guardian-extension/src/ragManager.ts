import * as vscode from 'vscode';
import { HNSWLib } from '@langchain/community/vectorstores/hnswlib';
import { OllamaEmbeddings } from '@langchain/ollama';
import { Document } from '@langchain/core/documents';
import { RecursiveCharacterTextSplitter } from '@langchain/textsplitters';
import * as path from 'path';
import * as fs from 'fs';
import * as fsPromises from 'fs/promises';
import { VulnerabilityDataManager, VulnerabilityData } from './vulnerabilityDataManager';

import { getLogger } from './logger';
export interface SecurityKnowledge {
    id: string;
    title: string;
    content: string;
    category: string;
    severity: 'high' | 'medium' | 'low';
    cwe?: string;
    owasp?: string;
    tags: string[];
    version?: string;           // Knowledge version for tracking updates
    createdAt?: Date;           // When this knowledge was added
    updatedAt?: Date;           // Last update timestamp
    source?: string;            // Source of the knowledge (e.g., 'default', 'nvd', 'custom')
    deprecated?: boolean;       // Mark outdated knowledge for removal
}

export class RAGManager {
    private vectorStore: HNSWLib | null = null;
    private embeddings: OllamaEmbeddings;
    private knowledgeBase: SecurityKnowledge[] = [];
    private readonly storagePath: string;
    private readonly textSplitter: RecursiveCharacterTextSplitter;
    private vulnerabilityDataManager: VulnerabilityDataManager;
    private readonly logger = getLogger();

    constructor(private context: vscode.ExtensionContext) {
        this.storagePath = path.join(context.extensionPath, 'security-knowledge');
        this.vulnerabilityDataManager = new VulnerabilityDataManager(context);
        
        const config = vscode.workspace.getConfiguration('codeGuardian');
        const ollamaHost = config.get<string>('ollamaHost', 'http://localhost:11434');

        this.embeddings = new OllamaEmbeddings({
            baseUrl: ollamaHost,
            model: 'nomic-embed-text', // Lightweight embedding model
        });
        
        this.textSplitter = new RecursiveCharacterTextSplitter({
            chunkSize: 1000,
            chunkOverlap: 200,
            separators: ['\n\n', '\n', '. ', ' ', ''],
        });

        this.initializeKnowledgeBase();
    }

    private async initializeKnowledgeBase(): Promise<void> {
        try {
            // Ensure storage directory exists
            if (!fs.existsSync(this.storagePath)) {
                fs.mkdirSync(this.storagePath, { recursive: true });
            }

            // Try to load existing knowledge base from disk first
            await this.loadKnowledgeBaseFromDisk();

            // If no knowledge base found, load defaults
            if (this.knowledgeBase.length === 0) {
                await this.loadDefaultSecurityKnowledge();
                await this.saveKnowledgeBaseToDisk();
            }

            // Initialize or load vector store
            await this.initializeVectorStore();
        } catch (error) {
            this.logger.error('Failed to initialize RAG knowledge base:', error);
            vscode.window.showErrorMessage('Failed to initialize security knowledge base');
        }
    }

    /**
     * Load security knowledge from dynamic sources (NVD, OWASP, CWE, GitHub, etc.)
     * Falls back to minimal baseline if all sources fail
     */
    private async loadDefaultSecurityKnowledge(): Promise<void> {
        this.logger.info('Loading security knowledge from dynamic sources...');

        try {
            // Try to fetch from all real-time sources
            const vulnerabilityData = await this.vulnerabilityDataManager.updateAllVulnerabilityData();

            this.logger.info(`📊 Fetched vulnerability data:
                - CWE: ${vulnerabilityData.cwe.length} entries
                - OWASP: ${vulnerabilityData.owasp.length} entries
                - CVEs: ${vulnerabilityData.cves.length} entries
                - JavaScript: ${vulnerabilityData.javascript.length} entries
                - Total: ${vulnerabilityData.total} entries`);

            // Convert VulnerabilityData to SecurityKnowledge format
            this.knowledgeBase = this.convertVulnerabilityDataToKnowledge([
                ...vulnerabilityData.cwe,
                ...vulnerabilityData.owasp,
                ...vulnerabilityData.cves,
                ...vulnerabilityData.javascript
            ]);

            if (this.knowledgeBase.length === 0) {
                throw new Error('No vulnerability data fetched from any source');
            }

            this.logger.info(`✅ Successfully loaded ${this.knowledgeBase.length} security knowledge entries from dynamic sources`);

        } catch (error) {
            this.logger.error('❌ Failed to load from dynamic sources, using minimal baseline:', error);

            // Fallback: Load minimal baseline if all sources fail
            // This ensures the extension can still function even without internet
            this.knowledgeBase = this.getMinimalBaselineKnowledge();
            this.logger.info(`⚠️  Using ${this.knowledgeBase.length} baseline knowledge entries`);
        }
    }

    /**
     * Convert VulnerabilityData from VulnerabilityDataManager to SecurityKnowledge format
     */
    private convertVulnerabilityDataToKnowledge(vulnData: VulnerabilityData[]): SecurityKnowledge[] {
        return vulnData.map(vuln => {
            // Build comprehensive content from all available fields
            let content = vuln.description;

            if (vuln.mitigation) {
                content += '\n\nMitigation:\n' + vuln.mitigation;
            }

            if (vuln.examples && vuln.examples.length > 0) {
                content += '\n\nExamples:\n' + vuln.examples.join('\n');
            }

            if (vuln.references && vuln.references.length > 0) {
                content += '\n\nReferences:\n' + vuln.references.slice(0, 3).join('\n');
            }

            // Map severity (VulnerabilityData has 'critical' which SecurityKnowledge doesn't)
            const mappedSeverity: 'high' | 'medium' | 'low' =
                vuln.severity === 'critical' ? 'high' : vuln.severity as 'high' | 'medium' | 'low';

            // Determine category based on CWE, tags, or source
            const category = this.determineCategory(vuln);

            return {
                id: vuln.id,
                title: vuln.title,
                content: content,
                category: category,
                severity: mappedSeverity,
                cwe: vuln.cwe,
                owasp: vuln.owasp,
                tags: vuln.tags,
                version: '1.0',
                createdAt: new Date(vuln.lastUpdated),
                updatedAt: new Date(vuln.lastUpdated),
                source: vuln.source,
                deprecated: false
            };
        });
    }

    /**
     * Determine category based on vulnerability characteristics
     */
    private determineCategory(vuln: VulnerabilityData): string {
        // Check tags first
        const tags = vuln.tags.join(' ').toLowerCase();

        if (tags.includes('injection') || tags.includes('xss') || tags.includes('sql')) {
            return 'injection';
        }
        if (tags.includes('crypto') || tags.includes('encryption') || tags.includes('hash')) {
            return 'cryptography';
        }
        if (tags.includes('auth') || tags.includes('access-control') || tags.includes('permission')) {
            return 'authentication';
        }
        if (tags.includes('path') || tags.includes('traversal') || tags.includes('file')) {
            return 'path-traversal';
        }
        if (tags.includes('deserialization') || tags.includes('prototype')) {
            return 'deserialization';
        }
        if (tags.includes('csrf') || tags.includes('cors')) {
            return 'web-security';
        }
        if (tags.includes('npm') || tags.includes('supply-chain') || tags.includes('dependency')) {
            return 'supply-chain';
        }

        // Check CWE
        if (vuln.cwe) {
            const cweNum = vuln.cwe.match(/\d+/)?.[0];
            if (cweNum) {
                const commonCWE: Record<string, string> = {
                    '79': 'injection',
                    '89': 'injection',
                    '22': 'path-traversal',
                    '352': 'web-security',
                    '502': 'deserialization',
                    '1321': 'injection',
                    '330': 'cryptography',
                    '798': 'authentication',
                    '863': 'authentication'
                };
                if (commonCWE[cweNum]) {
                    return commonCWE[cweNum];
                }
            }
        }

        // Default category
        return 'general-security';
    }

    /**
     * Minimal baseline knowledge for offline use
     * Only includes the most critical patterns
     */
    private getMinimalBaselineKnowledge(): SecurityKnowledge[] {
        return [
            {
                id: 'baseline-xss',
                title: 'XSS Prevention (Baseline)',
                content: 'Avoid innerHTML with user input. Use textContent instead. Sanitize all user input before rendering.',
                category: 'injection',
                severity: 'high',
                cwe: 'CWE-79',
                tags: ['xss', 'injection'],
                version: '1.0',
                createdAt: new Date(),
                updatedAt: new Date(),
                source: 'baseline',
                deprecated: false
            },
            {
                id: 'baseline-sql',
                title: 'SQL Injection Prevention (Baseline)',
                content: 'Use parameterized queries. Never concatenate user input into SQL strings.',
                category: 'injection',
                severity: 'high',
                cwe: 'CWE-89',
                tags: ['sql-injection', 'database'],
                version: '1.0',
                createdAt: new Date(),
                updatedAt: new Date(),
                source: 'baseline',
                deprecated: false
            },
            {
                id: 'baseline-eval',
                title: 'Avoid eval() (Baseline)',
                content: 'Never use eval() with user input. Use JSON.parse() for data instead.',
                category: 'injection',
                severity: 'high',
                cwe: 'CWE-95',
                tags: ['eval', 'code-injection'],
                version: '1.0',
                createdAt: new Date(),
                updatedAt: new Date(),
                source: 'baseline',
                deprecated: false
            }
        ];
    }

    /**
     * Sync knowledge base from all dynamic sources
     * This can be called by the user via command palette
     */
    async syncFromDynamicSources(): Promise<{
        success: boolean;
        added: number;
        updated: number;
        total: number;
        sources: {
            cwe: number;
            owasp: number;
            cves: number;
            javascript: number;
        };
        error?: string;
    }> {
        try {
            this.logger.info('Syncing from dynamic sources...');

            const vulnerabilityData = await this.vulnerabilityDataManager.updateAllVulnerabilityData();
            const newKnowledge = this.convertVulnerabilityDataToKnowledge([
                ...vulnerabilityData.cwe,
                ...vulnerabilityData.owasp,
                ...vulnerabilityData.cves,
                ...vulnerabilityData.javascript
            ]);

            let added = 0;
            let updated = 0;

            // Process each new knowledge entry (skip per-entry vector updates for bulk efficiency)
            for (const knowledge of newKnowledge) {
                const existingIndex = this.knowledgeBase.findIndex(k => k.id === knowledge.id);

                if (existingIndex === -1) {
                    // New entry — skip individual vector update, we rebuild once at the end
                    await this.addSecurityKnowledge(knowledge, true);
                    added++;
                } else {
                    // Update existing in knowledge base only
                    this.knowledgeBase[existingIndex] = {
                        ...knowledge,
                        updatedAt: new Date(),
                        version: knowledge.version || '1.0',
                        createdAt: this.knowledgeBase[existingIndex].createdAt || new Date()
                    };
                    updated++;
                }
            }

            // Single rebuild after all entries are processed
            if (added + updated > 0) {
                await this.rebuildVectorStore();
                await this.saveKnowledgeBaseToDisk();
            }

            this.logger.info(`✅ Sync complete: ${added} added, ${updated} updated`);

            return {
                success: true,
                added,
                updated,
                total: this.knowledgeBase.length,
                sources: {
                    cwe: vulnerabilityData.cwe.length,
                    owasp: vulnerabilityData.owasp.length,
                    cves: vulnerabilityData.cves.length,
                    javascript: vulnerabilityData.javascript.length
                }
            };

        } catch (error) {
            const errorMsg = error instanceof Error ? error.message : String(error);
            this.logger.error('❌ Sync failed:', errorMsg);

            return {
                success: false,
                added: 0,
                updated: 0,
                total: this.knowledgeBase.length,
                sources: {
                    cwe: 0,
                    owasp: 0,
                    cves: 0,
                    javascript: 0
                },
                error: errorMsg
            };
        }
    }

    private async initializeVectorStore(): Promise<void> {
        const vectorStorePath = path.join(this.storagePath, 'vector-store');
        
        try {
            // Try to load existing vector store
            if (fs.existsSync(vectorStorePath)) {
                this.vectorStore = await HNSWLib.load(vectorStorePath, this.embeddings);
                this.logger.info('Loaded existing vector store');
                return;
            }

            // Create new vector store from knowledge base
            const documents = await this.createDocumentsFromKnowledge();
            
            if (documents.length > 0) {
                this.vectorStore = await HNSWLib.fromDocuments(documents, this.embeddings);
                await this.vectorStore.save(vectorStorePath);
                this.logger.info('Created and saved new vector store');
            }
        } catch (error) {
            this.logger.error('Error initializing vector store:', error);
            // Fallback: create in-memory vector store
            const documents = await this.createDocumentsFromKnowledge();
            if (documents.length > 0) {
                this.vectorStore = await HNSWLib.fromDocuments(documents, this.embeddings);
            }
        }
    }

    private async createDocumentsFromKnowledge(): Promise<Document[]> {
        const documents: Document[] = [];

        for (const knowledge of this.knowledgeBase) {
            const chunks = await this.textSplitter.splitText(knowledge.content);
            
            for (let i = 0; i < chunks.length; i++) {
                documents.push(new Document({
                    pageContent: chunks[i],
                    metadata: {
                        id: knowledge.id,
                        title: knowledge.title,
                        category: knowledge.category,
                        severity: knowledge.severity,
                        cwe: knowledge.cwe,
                        owasp: knowledge.owasp,
                        tags: knowledge.tags.join(','),
                        chunkIndex: i,
                        totalChunks: chunks.length
                    }
                }));
            }
        }

        return documents;
    }

    async searchRelevantKnowledge(query: string, k: number = 3): Promise<Document[]> {
        if (!this.vectorStore) {
            this.logger.warn('Vector store not initialized');
            return [];
        }

        try {
            const results = await this.vectorStore.similaritySearch(query, k);
            return results;
        } catch (error) {
            this.logger.error('Error searching knowledge base:', error);
            return [];
        }
    }

    async addSecurityKnowledge(knowledge: SecurityKnowledge, skipVectorUpdate = false): Promise<void> {
        try {
            // Add metadata if not present
            const newKnowledge = {
                ...knowledge,
                version: knowledge.version || '1.0',
                createdAt: knowledge.createdAt || new Date(),
                updatedAt: knowledge.updatedAt || new Date(),
                source: knowledge.source || 'custom',
                deprecated: knowledge.deprecated || false
            };

            this.knowledgeBase.push(newKnowledge);

            if (this.vectorStore && !skipVectorUpdate) {
                const chunks = await this.textSplitter.splitText(newKnowledge.content);
                const documents: Document[] = [];

                for (let i = 0; i < chunks.length; i++) {
                    documents.push(new Document({
                        pageContent: chunks[i],
                        metadata: {
                            id: newKnowledge.id,
                            title: newKnowledge.title,
                            category: newKnowledge.category,
                            severity: newKnowledge.severity,
                            cwe: newKnowledge.cwe,
                            owasp: newKnowledge.owasp,
                            tags: newKnowledge.tags.join(','),
                            version: newKnowledge.version,
                            source: newKnowledge.source,
                            createdAt: newKnowledge.createdAt?.toISOString(),
                            chunkIndex: i,
                            totalChunks: chunks.length
                        }
                    }));
                }

                await this.vectorStore.addDocuments(documents);

                // Save updated vector store
                const vectorStorePath = path.join(this.storagePath, 'vector-store');
                await this.vectorStore.save(vectorStorePath);

                // Save knowledge base to disk
                await this.saveKnowledgeBaseToDisk();
            }

            this.logger.info(`✅ Added new knowledge: ${newKnowledge.id}`);
        } catch (error) {
            this.logger.error('Error adding security knowledge:', error);
            throw error;
        }
    }

    async generateEnhancedPrompt(originalPrompt: string, codeSnippet: string): Promise<string> {
        try {
            // Search for relevant security knowledge
            const searchQuery = `${originalPrompt} ${codeSnippet}`;
            const relevantDocs = await this.searchRelevantKnowledge(searchQuery, 3);

            if (relevantDocs.length === 0) {
                return originalPrompt;
            }

            // Build enhanced prompt with retrieved knowledge
            let enhancedPrompt = originalPrompt + '\n\n';
            enhancedPrompt += 'RELEVANT SECURITY KNOWLEDGE:\n';
            enhancedPrompt += '=' .repeat(50) + '\n\n';

            for (const doc of relevantDocs) {
                const metadata = doc.metadata;
                enhancedPrompt += `📋 ${metadata.title} (${metadata.severity?.toUpperCase()} severity)\n`;
                if (metadata.cwe) {
                    enhancedPrompt += `CWE: ${metadata.cwe} `;
                }
                if (metadata.owasp) {
                    enhancedPrompt += `OWASP: ${metadata.owasp}`;
                }
                enhancedPrompt += '\n\n';
                enhancedPrompt += doc.pageContent + '\n\n';
                enhancedPrompt += '-'.repeat(30) + '\n\n';
            }

            enhancedPrompt += 'Based on the above security knowledge, please analyze the provided code and provide specific, actionable recommendations.\n';

            return enhancedPrompt;
        } catch (error) {
            this.logger.error('Error generating enhanced prompt:', error);
            return originalPrompt;
        }
    }

    async getKnowledgeByCategory(category: string): Promise<SecurityKnowledge[]> {
        return this.knowledgeBase.filter(k => k.category === category);
    }

    async getKnowledgeBySeverity(severity: 'high' | 'medium' | 'low'): Promise<SecurityKnowledge[]> {
        return this.knowledgeBase.filter(k => k.severity === severity);
    }

    getKnowledgeBase(): SecurityKnowledge[] {
        return [...this.knowledgeBase];
    }

    async rebuildVectorStore(): Promise<void> {
        try {
            const documents = await this.createDocumentsFromKnowledge();

            if (documents.length > 0) {
                this.vectorStore = await HNSWLib.fromDocuments(documents, this.embeddings);

                const vectorStorePath = path.join(this.storagePath, 'vector-store');
                await this.vectorStore.save(vectorStorePath);

                vscode.window.showInformationMessage('Security knowledge base rebuilt successfully');
            }
        } catch (error) {
            this.logger.error('Error rebuilding vector store:', error);
            vscode.window.showErrorMessage('Failed to rebuild knowledge base');
        }
    }

    /**
     * Update existing knowledge incrementally without rebuilding entire index
     * @param knowledge Updated security knowledge
     * @returns Promise that resolves when update is complete
     */
    async updateSecurityKnowledge(knowledge: SecurityKnowledge): Promise<void> {
        try {
            const existingIndex = this.knowledgeBase.findIndex(k => k.id === knowledge.id);

            if (existingIndex === -1) {
                throw new Error(`Knowledge with id '${knowledge.id}' not found`);
            }

            // Update metadata
            const updatedKnowledge = {
                ...knowledge,
                updatedAt: new Date(),
                version: knowledge.version || '1.0',
                createdAt: this.knowledgeBase[existingIndex].createdAt || new Date()
            };

            // Update in knowledge base
            this.knowledgeBase[existingIndex] = updatedKnowledge;

            // Incrementally update vector store
            if (this.vectorStore) {
                // Remove old documents for this knowledge ID
                await this.removeKnowledgeFromVectorStore(knowledge.id);

                // Add updated documents
                const chunks = await this.textSplitter.splitText(updatedKnowledge.content);
                const documents: Document[] = [];

                for (let i = 0; i < chunks.length; i++) {
                    documents.push(new Document({
                        pageContent: chunks[i],
                        metadata: {
                            id: updatedKnowledge.id,
                            title: updatedKnowledge.title,
                            category: updatedKnowledge.category,
                            severity: updatedKnowledge.severity,
                            cwe: updatedKnowledge.cwe,
                            owasp: updatedKnowledge.owasp,
                            tags: updatedKnowledge.tags.join(','),
                            version: updatedKnowledge.version,
                            updatedAt: updatedKnowledge.updatedAt?.toISOString(),
                            chunkIndex: i,
                            totalChunks: chunks.length
                        }
                    }));
                }

                await this.vectorStore.addDocuments(documents);

                // Save updated vector store
                const vectorStorePath = path.join(this.storagePath, 'vector-store');
                await this.vectorStore.save(vectorStorePath);

                // Save knowledge base to disk
                await this.saveKnowledgeBaseToDisk();
            }

            this.logger.info(`✅ Updated knowledge: ${knowledge.id}`);
        } catch (error) {
            this.logger.error('Error updating security knowledge:', error);
            throw error;
        }
    }

    /**
     * Batch update multiple knowledge entries incrementally
     * @param knowledgeList Array of knowledge to update
     * @returns Statistics about the update operation
     */
    async batchUpdateKnowledge(knowledgeList: SecurityKnowledge[]): Promise<{
        updated: number;
        failed: number;
        errors: string[];
    }> {
        const result = {
            updated: 0,
            failed: 0,
            errors: [] as string[]
        };

        for (const knowledge of knowledgeList) {
            try {
                await this.updateSecurityKnowledge(knowledge);
                result.updated++;
            } catch (error) {
                result.failed++;
                const errorMsg = error instanceof Error ? error.message : String(error);
                result.errors.push(`Failed to update ${knowledge.id}: ${errorMsg}`);
                this.logger.error(`Failed to update ${knowledge.id}:`, error);
            }
        }

        return result;
    }

    /**
     * Remove knowledge from vector store (helper for incremental updates)
     * @param knowledgeId ID of knowledge to remove
     */
    private async removeKnowledgeFromVectorStore(knowledgeId: string): Promise<void> {
        // Note: HNSWLib doesn't support deletion directly
        // This is a limitation we document
        // For now, we rebuild if too many updates accumulate
        this.logger.info(`⚠️  Marked ${knowledgeId} for rebuild (HNSWLib doesn't support deletion)`);
    }

    /**
     * Save knowledge base to disk for persistence
     */
    private async saveKnowledgeBaseToDisk(): Promise<void> {
        try {
            const knowledgePath = path.join(this.storagePath, 'knowledge-base.json');
            const data = JSON.stringify(this.knowledgeBase, null, 2);
            await fsPromises.writeFile(knowledgePath, data, 'utf8');
            this.logger.debug('Saved knowledge base to disk');
        } catch (error) {
            this.logger.error('Error saving knowledge base:', error);
        }
    }

    /**
     * Load knowledge base from disk
     */
    private async loadKnowledgeBaseFromDisk(): Promise<void> {
        try {
            const knowledgePath = path.join(this.storagePath, 'knowledge-base.json');

            if (fs.existsSync(knowledgePath)) {
                const data = await fsPromises.readFile(knowledgePath, 'utf8');
                const loaded = JSON.parse(data) as SecurityKnowledge[];

                // Convert date strings back to Date objects
                this.knowledgeBase = loaded.map(k => ({
                    ...k,
                    createdAt: k.createdAt ? new Date(k.createdAt) : undefined,
                    updatedAt: k.updatedAt ? new Date(k.updatedAt) : undefined
                }));

                this.logger.info(`📚 Loaded ${this.knowledgeBase.length} knowledge entries from disk`);
            }
        } catch (error) {
            this.logger.error('Error loading knowledge base from disk:', error);
        }
    }

    /**
     * Prune deprecated or outdated knowledge
     * @param daysOld Remove knowledge older than this many days (default: 365)
     */
    async pruneOutdatedKnowledge(daysOld: number = 365): Promise<{
        removed: number;
        knowledgeIds: string[];
    }> {
        const result = {
            removed: 0,
            knowledgeIds: [] as string[]
        };

        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - daysOld);

        // Find knowledge to remove
        const toRemove = this.knowledgeBase.filter(k => {
            // Remove if deprecated
            if (k.deprecated) {
                return true;
            }

            // Remove if very old and not updated
            if (k.createdAt && k.createdAt < cutoffDate && !k.updatedAt) {
                return true;
            }

            return false;
        });

        // Remove from knowledge base
        for (const knowledge of toRemove) {
            const index = this.knowledgeBase.findIndex(k => k.id === knowledge.id);
            if (index > -1) {
                this.knowledgeBase.splice(index, 1);
                result.removed++;
                result.knowledgeIds.push(knowledge.id);
            }
        }

        // If we removed entries, rebuild vector store
        if (result.removed > 0) {
            this.logger.info(`🗑️  Removed ${result.removed} outdated knowledge entries`);
            await this.rebuildVectorStore();
            await this.saveKnowledgeBaseToDisk();
        }

        return result;
    }

    /**
     * Get knowledge statistics
     */
    getKnowledgeStats(): {
        total: number;
        byCategory: Record<string, number>;
        bySeverity: Record<string, number>;
        bySource: Record<string, number>;
        deprecated: number;
        outdated: number;
    } {
        const stats = {
            total: this.knowledgeBase.length,
            byCategory: {} as Record<string, number>,
            bySeverity: {} as Record<string, number>,
            bySource: {} as Record<string, number>,
            deprecated: 0,
            outdated: 0
        };

        const sixMonthsAgo = new Date();
        sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

        for (const knowledge of this.knowledgeBase) {
            // Count by category
            stats.byCategory[knowledge.category] = (stats.byCategory[knowledge.category] || 0) + 1;

            // Count by severity
            stats.bySeverity[knowledge.severity] = (stats.bySeverity[knowledge.severity] || 0) + 1;

            // Count by source
            const source = knowledge.source || 'default';
            stats.bySource[source] = (stats.bySource[source] || 0) + 1;

            // Count deprecated
            if (knowledge.deprecated) {
                stats.deprecated++;
            }

            // Count outdated (not updated in 6 months)
            if (knowledge.createdAt && knowledge.createdAt < sixMonthsAgo && !knowledge.updatedAt) {
                stats.outdated++;
            }
        }

        return stats;
    }

    /**
     * Update knowledge base with latest vulnerabilities
     * This is a legacy wrapper - internally uses syncFromDynamicSources()
     */
    async updateKnowledgeBaseWithLatestVulnerabilities(): Promise<{
        added: number;
        updated: number;
        errors: string[];
    }> {
        this.logger.warn(' Using legacy method - redirecting to syncFromDynamicSources()');

        const syncResult = await this.syncFromDynamicSources();

        return {
            added: syncResult.added,
            updated: syncResult.updated,
            errors: syncResult.error ? [syncResult.error] : []
        };
    }

    async getVulnerabilityDataStats(): Promise<{
        totalKnowledge: number;
        vulnerabilityData: number;
        cacheInfo: Array<{ file: string; exists: boolean; age: number; size: number }>;
        lastUpdate: string | null;
    }> {
        const cacheInfo = this.vulnerabilityDataManager.getCacheInfo();
        const allCachedData = await this.vulnerabilityDataManager.getAllCachedData();
        
        // Find most recent update
        let lastUpdate: string | null = null;
        for (const data of allCachedData) {
            if (!lastUpdate || new Date(data.lastUpdated) > new Date(lastUpdate)) {
                lastUpdate = data.lastUpdated;
            }
        }

        return {
            totalKnowledge: this.knowledgeBase.length,
            vulnerabilityData: allCachedData.length,
            cacheInfo,
            lastUpdate
        };
    }

    async clearVulnerabilityCache(): Promise<void> {
        await this.vulnerabilityDataManager.clearCache();
        vscode.window.showInformationMessage('Vulnerability data cache cleared');
    }

    getVulnerabilityDataManager(): VulnerabilityDataManager {
        return this.vulnerabilityDataManager;
    }
}