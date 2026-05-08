import os, re, glob
root = '/Users/hafiz/personal/repos/tuc-master-thesis/code-guardian-thesis-report'
texs = glob.glob(os.path.join(root, '**/*.tex'), recursive=True)
cites = {}
labels_def = {}
labels_used = {}
cite_re = re.compile(r'\\cite[a-zA-Z]*\{([^}]+)\}')
label_def_re = re.compile(r'\\label\{([^}]+)\}')
label_use_re = re.compile(r'\\(?:ref|eqref|autoref|cref|Cref|pageref|nameref|hyperref)\*?\{([^}]+)\}')
sentence_cite_violations = []
for t in texs:
    with open(t) as f:
        content = f.read()
    for i, line in enumerate(content.splitlines(), 1):
        for m in cite_re.findall(line):
            for k in m.split(','):
                cites.setdefault(k.strip(), []).append((t, i))
        for m in label_def_re.findall(line):
            labels_def.setdefault(m, []).append((t, i))
        for m in label_use_re.findall(line):
            for k in m.split(','):
                labels_used.setdefault(k.strip(), []).append((t, i))
    cleaned_lines = []
    for ln in content.splitlines():
        idx = 0
        while idx < len(ln):
            if ln[idx] == '%' and (idx == 0 or ln[idx-1] != '\\'):
                ln = ln[:idx]
                break
            idx += 1
        cleaned_lines.append(ln)
    cleaned = '\n'.join(cleaned_lines)
    def repl_cite(m):
        keys = [k.strip() for k in m.group(1).split(',')]
        return 'CITEMARK' + ('K'*len(keys))
    repl = cite_re.sub(repl_cite, cleaned)
    sentences = re.split(r'(?<=[.!?])\s+', repl)
    for s in sentences:
        marks = re.findall(r'CITEMARK(K+)', s)
        total = sum(len(m) for m in marks)
        if total >= 3:
            sentence_cite_violations.append((t, total, s[:240]))

bib_keys = set()
with open(os.path.join(root, 'bibliography.bib')) as f:
    for line in f:
        m = re.match(r'@[a-zA-Z]+\{([^,]+),', line)
        if m:
            bib_keys.add(m.group(1).strip())

print('=== Undefined citations ===')
undef_c = sorted(set(cites.keys()) - bib_keys)
for k in undef_c:
    print(repr(k), cites[k][:3])
print('Count:', len(undef_c))
print()
print('=== Undefined refs ===')
undef_r = sorted(set(labels_used.keys()) - set(labels_def.keys()))
for k in undef_r:
    print(repr(k), labels_used[k][:3])
print('Count:', len(undef_r))
print()
print('=== Duplicate label defs ===')
dups = 0
for k, v in sorted(labels_def.items()):
    if len(v) > 1:
        print(k, v)
        dups += 1
print('Count:', dups)
print()
print('=== Removed bib entries still cited? ===')
for k in ['li2023codewhisperer','githubAdvancedSecurity']:
    print(k, 'in bib?', k in bib_keys, 'cited?', k in cites)
print()
print('=== ding2024primevul ===')
print('in bib?', 'ding2024primevul' in bib_keys, 'cited?', 'ding2024primevul' in cites, cites.get('ding2024primevul'))
print()
print('=== Stale labels (should NOT be defined or used) ===')
for k in ['sec:conclusion-critical','sec:fw-engineering','sec:fw-methodology','sec:fw-research']:
    print(k, 'defined?', k in labels_def, 'used?', k in labels_used, labels_used.get(k))
print()
print('=== Required-resolve labels ===')
for k in ['chap:conclusion','sec:conclusion-limitations','tab:conclusion-deployment-profiles','chap:future-work','sec:conclusion-key-findings','sec:conclusion-implications']:
    print(k, 'defined?', k in labels_def, 'used count:', len(labels_used.get(k,[])))
print()
print('=== Sentence-level citation cap violations (>=3 keys) ===')
for v in sentence_cite_violations:
    print(v[0].replace(root+'/',''), 'keys=', v[1])
    print('  ', v[2][:200])
print('Count:', len(sentence_cite_violations))
print()
print('=== Unused bib entries ===')
unused = sorted(bib_keys - set(cites.keys()))
print('Count:', len(unused))
for k in unused:
    print(' ', k)
