// Adversarial test: NoSQL injection in aggregation pipeline
// CWE: CWE-943
// Severity: high
// Source: Adversarial - Original Pattern
// Vulnerable lines: [10]

// Adversarial: NoSQL injection via aggregation
function getUserAnalytics(userId, filters) {
    const pipeline = [
        { $match: { userId: userId } },
        { $group: { _id: "$category", total: { $sum: 1 } } }
    ];
    
    // Vulnerable: Direct filter injection
    if (filters.customStage) {
        pipeline.push(JSON.parse(filters.customStage));
    }
    
    return db.collection('events').aggregate(pipeline).toArray();
}