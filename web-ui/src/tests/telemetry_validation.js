/**
 * Standalone Node.js QA Validation Test Script
 * Zertree Telemetry & Risk Calculations QA Audit
 * File: web-ui/src/tests/telemetry_validation.js
 */

import assert from 'assert';

// ==========================================
// 1. ORIGINAL IMPLEMENTATIONS (from App.svelte)
// ==========================================

function auditLicenseExpressionOriginal(expr, blockedList) {
  if (!expr) return { risk: 'unknown', text: 'No License' };
  const normalized = expr.toUpperCase().replace(/[()]/g, '');
  
  // Check OR compound license
  if (normalized.includes(' OR ')) {
    const parts = normalized.split(' OR ');
    const outcomes = parts.map(p => auditLicenseExpressionOriginal(p.trim(), blockedList));
    // Choose safest (lowest risk): ok > warning > critical
    const hasOk = outcomes.some(o => o.risk === 'ok');
    if (hasOk) return { risk: 'ok', text: expr };
    const hasWarning = outcomes.some(o => o.risk === 'warning');
    if (hasWarning) return { risk: 'warning', text: expr };
    return { risk: 'critical', text: expr };
  } 
  
  // Check AND compound license
  if (normalized.includes(' AND ')) {
    const parts = normalized.split(' AND ');
    const outcomes = parts.map(p => auditLicenseExpressionOriginal(p.trim(), blockedList));
    // Must comply with both (worst risk): critical > warning > ok
    const hasCritical = outcomes.some(o => o.risk === 'critical');
    if (hasCritical) return { risk: 'critical', text: expr };
    const hasWarning = outcomes.some(o => o.risk === 'warning');
    if (hasWarning) return { risk: 'warning', text: expr };
    return { risk: 'ok', text: expr };
  }
  
  // Single license check
  const name = normalized.trim();
  if (blockedList.some(bl => name.includes(bl.toUpperCase()))) {
    return { risk: 'critical', text: expr };
  }
  if (name.includes('GPL') || name.includes('AGPL') || name.includes('SSPL')) {
    return { risk: 'warning', text: expr };
  }
  if (name.includes('MIT') || name.includes('APACHE') || name.includes('BSD') || name.includes('ISC')) {
    return { risk: 'ok', text: expr };
  }
  return { risk: 'unknown', text: expr };
}

function calculateTransitiveMetricsOriginal(components, dependencies, rules) {
  const adj = {};
  const revAdj = {};
  
  components.forEach(c => {
    adj[c.name] = new Set();
    revAdj[c.name] = new Set();
  });
  
  dependencies.forEach(dep => {
    const parentName = components.find(c => dep.ref === c.purl || dep.ref.includes(c.name))?.name;
    if (parentName && dep.dependsOn) {
      dep.dependsOn.forEach(targetRef => {
        const childName = components.find(c => targetRef === c.purl || targetRef.includes(c.name))?.name;
        if (childName && parentName !== childName) {
          adj[parentName].add(childName);
          revAdj[childName].add(parentName);
        }
      });
    }
  });
  
  function getTransitiveSet(nodeName, map) {
    const visited = new Set();
    const queue = [nodeName];
    while (queue.length > 0) {
      const curr = queue.shift();
      if (map[curr]) {
        map[curr].forEach(neigh => {
          if (!visited.has(neigh)) {
            visited.add(neigh);
            queue.push(neigh);
          }
        });
      }
    }
    return visited;
  }
  
  components.forEach(c => {
    const downstream = getTransitiveSet(c.name, adj);
    const upstream = getTransitiveSet(c.name, revAdj);
    
    c.dependenciesCount = downstream.size;
    c.blastRadius = upstream.size;
    
    // Calculate score based on self + inherited transitive vulnerability exposure
    let worstDownstreamCVSS = 0;
    downstream.forEach(childName => {
      const childComp = components.find(comp => comp.name === childName);
      if (childComp && childComp.cves && childComp.cves.length > 0) {
        const maxCVSS = Math.max(...childComp.cves.map(v => v.cvss_score || 0));
        if (maxCVSS > worstDownstreamCVSS) {
          worstDownstreamCVSS = maxCVSS;
        }
      }
    });
    
    // Cascading score formula
    let selfScore = c.score || 0;
    if (c.score === undefined) {
      let selfCveScore = 0;
      if (c.cves && c.cves.length > 0) {
        selfCveScore = Math.max(...c.cves.map(v => v.cvss_score || 0));
      }
      
      let licenseScore = rules.license_unknown_score || 5;
      const licExpr = (c.license || (c.licenses && c.licenses[0]?.license?.id) || c.licenses?.[0]?.license?.name || '');
      const audit = auditLicenseExpressionOriginal(licExpr, rules.blocked_licenses);
      if (audit.risk === 'critical') licenseScore = 10;
      else if (audit.risk === 'warning') licenseScore = 8;
      else if (audit.risk === 'ok') licenseScore = 0;
      
      selfScore = selfCveScore * rules.cve_weight + licenseScore * rules.license_weight;
    }
    
    c.score = Math.min(10.0, selfScore);
    c.cascadingScore = Math.min(10.0, selfScore + worstDownstreamCVSS * 0.22);
  });
}

// ==========================================
// 2. OPTIMIZED & FIXED IMPLEMENTATIONS
// ==========================================

function tokenizeLicenseExpression(expr) {
  const regex = /\s*(\(|\)|\bAND\b|\bOR\b)\s*/gi;
  return expr.split(regex)
    .map(p => p.trim())
    .filter(p => p.length > 0);
}

function parseLicenseTokens(tokens) {
  let index = 0;
  
  function peek() {
    return tokens[index];
  }
  
  function consume() {
    return tokens[index++];
  }
  
  function parseFactor() {
    const token = peek();
    if (token === '(') {
      consume(); // consume '('
      const node = parseExpr();
      if (peek() === ')') {
        consume(); // consume ')'
      }
      return node;
    }
    const name = consume();
    return { type: 'license', name };
  }
  
  function parseTerm() {
    let node = parseFactor();
    while (peek() && peek().toUpperCase() === 'AND') {
      consume(); // consume 'AND'
      const right = parseFactor();
      if (node.type === 'and') {
        node.operands.push(right);
      } else {
        node = { type: 'and', operands: [node, right] };
      }
    }
    return node;
  }
  
  function parseExpr() {
    let node = parseTerm();
    while (peek() && peek().toUpperCase() === 'OR') {
      consume(); // consume 'OR'
      const right = parseTerm();
      if (node.type === 'or') {
        node.operands.push(right);
      } else {
        node = { type: 'or', operands: [node, right] };
      }
    }
    return node;
  }
  
  return parseExpr();
}

function auditSingleLicenseFixed(name, blockedList) {
  const norm = name.toUpperCase().trim();
  
  const isBlocked = blockedList.some(bl => {
    const blNorm = bl.toUpperCase().trim();
    if (norm === blNorm) return true;
    
    const isPrefixMatch = norm.startsWith(blNorm + '-') || norm.startsWith(blNorm + '_');
    return isPrefixMatch;
  });
  
  if (isBlocked) {
    return { risk: 'critical', text: name };
  }
  
  if (norm.includes('AGPL') || norm.includes('SSPL') || norm.includes('GPL')) {
    return { risk: 'warning', text: name };
  }
  if (norm.includes('MIT') || norm.includes('APACHE') || norm.includes('BSD') || norm.includes('ISC')) {
    return { risk: 'ok', text: name };
  }
  return { risk: 'unknown', text: name };
}

function evaluateLicenseAST(node, blockedList) {
  if (!node) return { risk: 'unknown' };
  
  if (node.type === 'license') {
    return auditSingleLicenseFixed(node.name, blockedList);
  }
  
  const riskRank = { 'ok': 0, 'unknown': 1, 'warning': 2, 'critical': 3 };
  
  if (node.type === 'or') {
    const outcomes = node.operands.map(op => evaluateLicenseAST(op, blockedList));
    let safest = outcomes[0];
    for (let i = 1; i < outcomes.length; i++) {
      if (riskRank[outcomes[i].risk] < riskRank[safest.risk]) {
        safest = outcomes[i];
      }
    }
    return { risk: safest.risk };
  }
  
  if (node.type === 'and') {
    const outcomes = node.operands.map(op => evaluateLicenseAST(op, blockedList));
    let worst = outcomes[0];
    for (let i = 1; i < outcomes.length; i++) {
      if (riskRank[outcomes[i].risk] > riskRank[worst.risk]) {
        worst = outcomes[i];
      }
    }
    return { risk: worst.risk };
  }
  
  return { risk: 'unknown' };
}

function auditLicenseExpressionFixed(expr, blockedList) {
  if (!expr) return { risk: 'unknown', text: 'No License' };
  const cleaned = expr.trim();
  if (cleaned === '') return { risk: 'unknown', text: 'No License' };
  
  try {
    const tokens = tokenizeLicenseExpression(cleaned);
    if (tokens.length === 0) return { risk: 'unknown', text: expr };
    const ast = parseLicenseTokens(tokens);
    const result = evaluateLicenseAST(ast, blockedList);
    return { risk: result.risk, text: expr };
  } catch (err) {
    return { risk: 'unknown', text: expr };
  }
}

function calculateTransitiveMetricsFixed(components, dependencies, rules) {
  const adj = {};
  const revAdj = {};
  
  const compMap = new Map();
  const purlMap = new Map();
  
  components.forEach(c => {
    adj[c.name] = new Set();
    revAdj[c.name] = new Set();
    compMap.set(c.name, c);
    if (c.purl) purlMap.set(c.purl, c);
  });
  
  function getComponentByRef(ref) {
    if (!ref) return null;
    if (purlMap.has(ref)) return purlMap.get(ref);
    
    for (let i = 0; i < components.length; i++) {
      const c = components[i];
      if (ref === c.purl || ref.includes(c.name)) {
        return c;
      }
    }
    return null;
  }
  
  dependencies.forEach(dep => {
    const parent = getComponentByRef(dep.ref);
    if (parent && dep.dependsOn) {
      dep.dependsOn.forEach(targetRef => {
        const child = getComponentByRef(targetRef);
        if (child && parent.name !== child.name) {
          adj[parent.name].add(child.name);
          revAdj[child.name].add(parent.name);
        }
      });
    }
  });
  
  function getTransitiveSet(nodeName, map) {
    const visited = new Set();
    const queue = [nodeName];
    while (queue.length > 0) {
      const curr = queue.shift();
      if (map[curr]) {
        map[curr].forEach(neigh => {
          if (!visited.has(neigh)) {
            visited.add(neigh);
            queue.push(neigh);
          }
        });
      }
    }
    return visited;
  }
  
  components.forEach(c => {
    const downstream = getTransitiveSet(c.name, adj);
    const upstream = getTransitiveSet(c.name, revAdj);
    
    c.dependenciesCount = downstream.size;
    c.blastRadius = upstream.size;
    
    let worstDownstreamCVSS = 0;
    downstream.forEach(childName => {
      const childComp = compMap.get(childName);
      if (childComp && childComp.cves && childComp.cves.length > 0) {
        const maxCVSS = Math.max(...childComp.cves.map(v => v.cvss_score || 0));
        if (maxCVSS > worstDownstreamCVSS) {
          worstDownstreamCVSS = maxCVSS;
        }
      }
    });
    
    let selfScore = c.score || 0;
    if (c.score === undefined) {
      let selfCveScore = 0;
      if (c.cves && c.cves.length > 0) {
        selfCveScore = Math.max(...c.cves.map(v => v.cvss_score || 0));
      }
      
      let licenseScore = rules.license_unknown_score || 5;
      const licExpr = (c.license || (c.licenses && c.licenses[0]?.license?.id) || c.licenses?.[0]?.license?.name || '');
      const audit = auditLicenseExpressionFixed(licExpr, rules.blocked_licenses);
      if (audit.risk === 'critical') licenseScore = 10;
      else if (audit.risk === 'warning') licenseScore = 8;
      else if (audit.risk === 'ok') licenseScore = 0;
      
      selfScore = selfCveScore * rules.cve_weight + licenseScore * rules.license_weight;
    }
    
    c.score = Math.min(10.0, selfScore);
    c.cascadingScore = Math.min(10.0, selfScore + worstDownstreamCVSS * 0.22);
  });
}

// ==========================================
// 3. QA AUDIT TEST SUITE (18 EDGE CASES)
// ==========================================

const defaultRules = {
  cve_weight: 0.60,
  license_weight: 0.40,
  blocked_licenses: ['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0'],
  license_unknown_score: 5.0
};

const results = [];

function runTestCase(name, testFn) {
  try {
    testFn();
    results.push({ name, status: 'PASSED', error: null });
  } catch (err) {
    results.push({ name, status: 'FAILED', error: err.message });
  }
}

console.log("=== STARTING QA TELEMETRY & RISK CALCULATIONS AUDIT ===\n");

runTestCase("1. Simple OK License (Case Insensitivity)", () => {
  const r1 = auditLicenseExpressionOriginal("mit", defaultRules.blocked_licenses);
  const r2 = auditLicenseExpressionFixed("mit", defaultRules.blocked_licenses);
  assert.strictEqual(r1.risk, "ok");
  assert.strictEqual(r2.risk, "ok");
});

runTestCase("2. Simple Blocked License", () => {
  const r1 = auditLicenseExpressionOriginal("GPL-3.0", defaultRules.blocked_licenses);
  const r2 = auditLicenseExpressionFixed("GPL-3.0", defaultRules.blocked_licenses);
  assert.strictEqual(r1.risk, "critical");
  assert.strictEqual(r2.risk, "critical");
});

runTestCase("3. License Warning Fallback", () => {
  const r1 = auditLicenseExpressionOriginal("GPL-2.0", defaultRules.blocked_licenses);
  const r2 = auditLicenseExpressionFixed("GPL-2.0", defaultRules.blocked_licenses);
  assert.strictEqual(r1.risk, "warning");
  assert.strictEqual(r2.risk, "warning");
});

runTestCase("4. Blocked License Partial Matching (Over-matching Bug)", () => {
  const r1 = auditLicenseExpressionOriginal("LGPL-3.0", defaultRules.blocked_licenses);
  const r2 = auditLicenseExpressionFixed("LGPL-3.0", defaultRules.blocked_licenses);
  assert.strictEqual(r1.risk, "critical"); // Original fails
  assert.strictEqual(r2.risk, "warning");  // Fixed passes
});

runTestCase("5. Empty/Null License Handling", () => {
  const r1 = auditLicenseExpressionOriginal("", defaultRules.blocked_licenses);
  const r2 = auditLicenseExpressionFixed("", defaultRules.blocked_licenses);
  assert.strictEqual(r1.risk, "unknown");
  assert.strictEqual(r2.risk, "unknown");
});

runTestCase("6. Compound OR operator safest choice", () => {
  const r1 = auditLicenseExpressionOriginal("MIT OR GPL-3.0", defaultRules.blocked_licenses);
  const r2 = auditLicenseExpressionFixed("MIT OR GPL-3.0", defaultRules.blocked_licenses);
  assert.strictEqual(r1.risk, "ok");
  assert.strictEqual(r2.risk, "ok");
});

runTestCase("7. Compound AND operator worst choice", () => {
  const r1 = auditLicenseExpressionOriginal("MIT AND GPL-3.0", defaultRules.blocked_licenses);
  const r2 = auditLicenseExpressionFixed("MIT AND GPL-3.0", defaultRules.blocked_licenses);
  assert.strictEqual(r1.risk, "critical");
  assert.strictEqual(r2.risk, "critical");
});

runTestCase("8. Nested Parenthesis Precedence Bypass (Critical Security Bypass)", () => {
  const expr = "GPL-3.0 AND (MIT OR BSD)";
  const r1 = auditLicenseExpressionOriginal(expr, defaultRules.blocked_licenses);
  const r2 = auditLicenseExpressionFixed(expr, defaultRules.blocked_licenses);
  assert.strictEqual(r1.risk, "ok");       // Original fails (bypass!)
  assert.strictEqual(r2.risk, "critical"); // Fixed passes
});

runTestCase("9. Safest OR choice with UNKNOWN license (Bug in risk ordering)", () => {
  const expr = "Proprietary-9.9 OR GPL-3.0";
  const r1 = auditLicenseExpressionOriginal(expr, defaultRules.blocked_licenses);
  const r2 = auditLicenseExpressionFixed(expr, defaultRules.blocked_licenses);
  assert.strictEqual(r1.risk, "critical"); // Original fails
  assert.strictEqual(r2.risk, "unknown");  // Fixed passes
});

runTestCase("10. Worst AND choice with UNKNOWN license (Bug in risk ordering)", () => {
  const expr = "MIT AND Proprietary-9.9";
  const r1 = auditLicenseExpressionOriginal(expr, defaultRules.blocked_licenses);
  const r2 = auditLicenseExpressionFixed(expr, defaultRules.blocked_licenses);
  assert.strictEqual(r1.risk, "ok");      // Original under-assess risk
  assert.strictEqual(r2.risk, "unknown"); // Fixed passes
});

runTestCase("11. Score Capping at 10.0", () => {
  const components = [
    { name: "A", purl: "pkg:npm/A", cves: [{ id: "CVE-1", cvss_score: 10.0 }], license: "GPL-3.0" },
    { name: "B", purl: "pkg:npm/B", cves: [{ id: "CVE-2", cvss_score: 10.0 }], license: "MIT" }
  ];
  const dependencies = [
    { ref: "pkg:npm/A", dependsOn: ["pkg:npm/B"] }
  ];
  
  const componentsOrig = JSON.parse(JSON.stringify(components));
  const componentsFixed = JSON.parse(JSON.stringify(components));
  
  calculateTransitiveMetricsOriginal(componentsOrig, dependencies, defaultRules);
  calculateTransitiveMetricsFixed(componentsFixed, dependencies, defaultRules);
  
  assert.strictEqual(componentsOrig[0].score, 10.0);
  assert.strictEqual(componentsOrig[0].cascadingScore, 10.0);
  assert.strictEqual(componentsFixed[0].score, 10.0);
  assert.strictEqual(componentsFixed[0].cascadingScore, 10.0);
});

runTestCase("12. Empty/No Dependencies", () => {
  const components = [
    { name: "A", purl: "pkg:npm/A", cves: [], license: "MIT" }
  ];
  const componentsFixed = JSON.parse(JSON.stringify(components));
  
  calculateTransitiveMetricsFixed(componentsFixed, [], defaultRules);
  
  assert.strictEqual(componentsFixed[0].dependenciesCount, 0);
  assert.strictEqual(componentsFixed[0].blastRadius, 0);
  assert.strictEqual(componentsFixed[0].cascadingScore, 0.0);
});

runTestCase("13. Transitive Propagation along Deep Chains", () => {
  const components = [
    { name: "A", purl: "pkg:npm/A", license: "MIT" },
    { name: "B", purl: "pkg:npm/B", license: "MIT" },
    { name: "C", purl: "pkg:npm/C", license: "MIT" },
    { name: "D", purl: "pkg:npm/D", license: "MIT" },
    { name: "E", purl: "pkg:npm/E", license: "MIT", cves: [{ id: "CVE-E", cvss_score: 9.5 }] }
  ];
  const dependencies = [
    { ref: "pkg:npm/A", dependsOn: ["pkg:npm/B"] },
    { ref: "pkg:npm/B", dependsOn: ["pkg:npm/C"] },
    { ref: "pkg:npm/C", dependsOn: ["pkg:npm/D"] },
    { ref: "pkg:npm/D", dependsOn: ["pkg:npm/E"] }
  ];
  
  const componentsFixed = JSON.parse(JSON.stringify(components));
  calculateTransitiveMetricsFixed(componentsFixed, dependencies, defaultRules);
  
  assert.strictEqual(componentsFixed[0].dependenciesCount, 4);
  assert.strictEqual(componentsFixed[4].blastRadius, 4);
  const approx = (val, target, epsilon = 0.01) => assert.ok(Math.abs(val - target) < epsilon, `${val} not close to ${target}`);
  approx(componentsFixed[0].cascadingScore, 2.09);
});

runTestCase("14. Cycle Handling - Self Loop (A -> A)", () => {
  const components = [
    { name: "A", purl: "pkg:npm/A", license: "MIT", cves: [{ id: "CVE-A", cvss_score: 5.0 }] }
  ];
  const dependencies = [
    { ref: "pkg:npm/A", dependsOn: ["pkg:npm/A"] }
  ];
  const componentsFixed = JSON.parse(JSON.stringify(components));
  calculateTransitiveMetricsFixed(componentsFixed, dependencies, defaultRules);
  assert.strictEqual(componentsFixed[0].dependenciesCount, 0);
});

runTestCase("15. Cycle Handling - Direct Cycle (A -> B -> A)", () => {
  const components = [
    { name: "A", purl: "pkg:npm/A", license: "MIT" },
    { name: "B", purl: "pkg:npm/B", license: "MIT", cves: [{ id: "CVE-B", cvss_score: 8.0 }] }
  ];
  const dependencies = [
    { ref: "pkg:npm/A", dependsOn: ["pkg:npm/B"] },
    { ref: "pkg:npm/B", dependsOn: ["pkg:npm/A"] }
  ];
  const componentsFixed = JSON.parse(JSON.stringify(components));
  calculateTransitiveMetricsFixed(componentsFixed, dependencies, defaultRules);
  assert.strictEqual(componentsFixed[0].dependenciesCount, 2);
  assert.strictEqual(componentsFixed[1].dependenciesCount, 2);
  assert.strictEqual(componentsFixed[0].blastRadius, 2);
});

runTestCase("16. Cycle Handling - Indirect Cycle (A -> B -> C -> A)", () => {
  const components = [
    { name: "A", purl: "pkg:npm/A", license: "MIT" },
    { name: "B", purl: "pkg:npm/B", license: "MIT" },
    { name: "C", purl: "pkg:npm/C", license: "MIT", cves: [{ id: "CVE-C", cvss_score: 9.0 }] }
  ];
  const dependencies = [
    { ref: "pkg:npm/A", dependsOn: ["pkg:npm/B"] },
    { ref: "pkg:npm/B", dependsOn: ["pkg:npm/C"] },
    { ref: "pkg:npm/C", dependsOn: ["pkg:npm/A"] }
  ];
  const componentsFixed = JSON.parse(JSON.stringify(components));
  calculateTransitiveMetricsFixed(componentsFixed, dependencies, defaultRules);
  assert.strictEqual(componentsFixed[0].dependenciesCount, 3);
  assert.strictEqual(componentsFixed[0].blastRadius, 3);
});

runTestCase("17. Case Sensitivity on Grouped / Nested Expressions", () => {
  const expr = "(mit or gpl-3.0) and agpl-3.0";
  const r2 = auditLicenseExpressionFixed(expr, defaultRules.blocked_licenses);
  assert.strictEqual(r2.risk, "critical");
});

runTestCase("18. Score Capping with Custom Heavy Weights", () => {
  const heavyRules = {
    cve_weight: 2.0,
    license_weight: 3.0,
    blocked_licenses: ['GPL-3.0'],
    license_unknown_score: 5.0
  };
  const components = [
    { name: "A", purl: "pkg:npm/A", license: "GPL-3.0", cves: [{ id: "CVE-1", cvss_score: 10.0 }] }
  ];
  const componentsFixed = JSON.parse(JSON.stringify(components));
  calculateTransitiveMetricsFixed(componentsFixed, [], heavyRules);
  assert.strictEqual(componentsFixed[0].score, 10.0);
  assert.strictEqual(componentsFixed[0].cascadingScore, 10.0);
});

// Print test report
console.log("\n=== TEST EXECUTION SUMMARY ===");
let passed = 0, failed = 0;
results.forEach(r => {
  if (r.status === 'PASSED') {
    console.log(`[PASS] ${r.name}`);
    passed++;
  } else {
    console.log(`[FAIL] ${r.name} - Error: ${r.error}`);
    failed++;
  }
});
console.log(`\nPassed: ${passed}/${results.length} tests`);

// ==========================================
// 4. PERFORMANCE & LOAD STABILITY TESTING
// ==========================================

console.log("\n=== PERFORMANCE & LOAD TESTING (1000 NODES) ===");

// We pad names to 5 digits so that no name is a substring of another.
// e.g. "pkg_00001" does not contain "pkg_00002"
function generateLargeSbom(numNodes, dependencyFactor = 5) {
  const comps = [];
  const deps = [];
  
  for (let i = 0; i < numNodes; i++) {
    const padName = `pkg_${String(i).padStart(5, '0')}`;
    comps.push({
      name: padName,
      purl: `pkg:npm/${padName}`,
      cves: i % 10 === 0 ? [{ id: `CVE-${i}`, cvss_score: 7.5 }] : [],
      license: i % 7 === 0 ? "GPL-3.0" : "MIT"
    });
    
    const dependsOn = [];
    // Each node i depends on i+1, i+2, i+3, i+4, i+5 (with wrap-around)
    for (let d = 0; d < dependencyFactor; d++) {
      let targetIndex = (i + 1 + d) % numNodes;
      if (targetIndex !== i) {
        const targetPadName = `pkg_${String(targetIndex).padStart(5, '0')}`;
        dependsOn.push(`pkg:npm/${targetPadName}`);
      }
    }
    
    deps.push({
      ref: `pkg:npm/${padName}`,
      dependsOn: dependsOn
    });
  }
  
  return { components: comps, dependencies: deps };
}

const largeSbomOrig = generateLargeSbom(1000, 5);
const largeSbomFixed = JSON.parse(JSON.stringify(largeSbomOrig));

console.log(`Generated mock SBOM with:`);
console.log(`  - Components: ${largeSbomOrig.components.length}`);
console.log(`  - Dependency mappings: ${largeSbomOrig.dependencies.length} nodes (each with ~5 target links)`);

// Diagnostic: Check if adjacency lists are actually built
console.log("\nRunning diagnostic checks on graph resolution...");

const diagComponentsOrig = JSON.parse(JSON.stringify(largeSbomOrig.components));
const diagDependencies = largeSbomOrig.dependencies;

calculateTransitiveMetricsOriginal(diagComponentsOrig, diagDependencies, defaultRules);
console.log(`Original Metrics Diagnostic (First 3 components):`);
for(let i=0; i<3; i++) {
  console.log(`  - ${diagComponentsOrig[i].name}: dependenciesCount=${diagComponentsOrig[i].dependenciesCount}, blastRadius=${diagComponentsOrig[i].blastRadius}, cascadingScore=${diagComponentsOrig[i].cascadingScore.toFixed(2)}`);
}

const diagComponentsFixed = JSON.parse(JSON.stringify(largeSbomOrig.components));
calculateTransitiveMetricsFixed(diagComponentsFixed, diagDependencies, defaultRules);
console.log(`Fixed/Optimized Metrics Diagnostic (First 3 components):`);
for(let i=0; i<3; i++) {
  console.log(`  - ${diagComponentsFixed[i].name}: dependenciesCount=${diagComponentsFixed[i].dependenciesCount}, blastRadius=${diagComponentsFixed[i].blastRadius}, cascadingScore=${diagComponentsFixed[i].cascadingScore.toFixed(2)}`);
}

console.log("\nRunning original calculateTransitiveMetrics (O(N^3))...");
const startOrig = Date.now();
calculateTransitiveMetricsOriginal(largeSbomOrig.components, largeSbomOrig.dependencies, defaultRules);
const durationOrig = Date.now() - startOrig;
console.log(`Original implementation execution time: ${durationOrig}ms`);

console.log("\nRunning optimized calculateTransitiveMetrics (O(N^2))...");
const startFixed = Date.now();
calculateTransitiveMetricsFixed(largeSbomFixed.components, largeSbomFixed.dependencies, defaultRules);
const durationFixed = Date.now() - startFixed;
console.log(`Optimized implementation execution time: ${durationFixed}ms`);

console.log(`\nPerformance Speedup: ${(durationOrig / durationFixed).toFixed(1)}x faster!`);
console.log("\n=== QA AUDIT COMPLETE ===");
