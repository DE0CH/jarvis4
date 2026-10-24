export const meta = {
  name: 'jarvis4-grant-audit',
  description: 'Audit Jarvis 4: nothing advertised as core-gated can happen without the core; the core is minimal and stateless',
  phases: [
    { title: 'Inventory', detail: 'every advertised core-gated action and the core surface' },
    { title: 'Audit', detail: 'bypass hunt per component + core minimality' },
    { title: 'Verify', detail: 'adversarially refute each finding' },
  ],
}

const REPO = (args && args.repo) || '/home/claude/workspace/jarvis2'
const CTX = `Repo: ${REPO} (DE0CH/jarvis2, main). Read-only: do NOT edit, commit or run anything that changes state (no Fly, no setup.py writes, no pushes). Read docs/DESIGN.md (trust boundary: the router, the box, k3s/Flux and our own code are UNTRUSTED; the core, the iPhone, providers and the kernel are trusted), docs/API.md and docs/DECISIONS.md. Note: k8s/apps/core.yaml has a 'jarvis2/core-pin: hold' annotation by design.`

const REQ = `Deyao's two requirements:
(R1) Whenever something is advertised (docs, API, app text, comments) as needing a grant/approval from the core (phone Face ID signature, a core-signed cert, a core-issued grant, an unlock), there must be NO way to achieve the same effect without it — not through the router, a session machine, a different endpoint, a replay, a stale or reused approval, a race, a confused-deputy path, a misconfiguration the code permits, an env var, a file the machine trusts, Fly/GitHub/S3 credentials held outside the core, or a code path that skips the check.
(R2) The core is as small as it can be and as stateless as it can be: any logic, state, endpoint or branch in core/ that could live outside it (with the core only signing/verifying/accepting or rejecting) is a finding.`

const INV = {type:'object',properties:{gated:{type:'array',items:{type:'object',properties:{action:{type:'string'},advertisedWhere:{type:'string'},coreCheck:{type:'string'},effect:{type:'string'}},required:['action','advertisedWhere','coreCheck','effect']}},coreSurface:{type:'string'}},required:['gated','coreSurface']}
const FIND = {type:'object',properties:{findings:{type:'array',items:{type:'object',properties:{title:{type:'string'},requirement:{type:'string',enum:['R1','R2']},file:{type:'string'},line:{type:'integer'},scenario:{type:'string'},severity:{type:'string',enum:['critical','high','medium','low']},fix:{type:'string'}},required:['title','requirement','file','scenario','severity','fix']}}},required:['findings']}
const VERD = {type:'object',properties:{results:{type:'array',items:{type:'object',properties:{title:{type:'string'},verdict:{type:'string',enum:['confirmed','plausible','refuted']},reason:{type:'string'}},required:['title','verdict','reason']}}},required:['results']}

phase('Inventory')
const inv = await agent(`${CTX}\n\n${REQ}\n\nBuild the inventory: (1) every action that docs/API/app/comments say requires the core's grant/approval (phone signature, cert, grant, unlock, deploy key, add-store, resume-upgrade, restore, task, terminal/holder grants, standing rules, Inbox requests, store writes, claim/Reset/Recover/wipe, kill, input attestation, carried secrets…) with where it's advertised, which core function enforces it, and the real-world effect it guards (e.g. "a machine gets store X's values"). (2) A compact description of the core's whole surface: endpoints, state it keeps, branches.`, {label:'inventory', schema: INV})

const invText = JSON.stringify(inv)
const AREAS = [
  {key:'core', p:'core/ itself: does every primitive check what it claims (signatures over the exact payload, nonce/replay, one-use approvals, store set equality, image digest, predecessor killed, per-session unlock scope, carried-secret binding, deploy-key token scope)? Any path that releases plaintext or signs without the advertised proof?'},
  {key:'router', p:'router/: can the router (or anyone reaching it) achieve a gated effect without the core: e.g. exec into machines without a grant, deliver inputs, read secrets, start/restore/resume with different stores/options, make deploy keys, approve Inbox requests, forge caller identity, reuse approvals? Also endpoints that skip Access/auth.'},
  {key:'machine', p:'machine/ and session-image/: does the machine accept anything it should refuse (exec without grant, unvouched inputs, env, snapshots, repos, credentials, allow-list self-grants a feature that is advertised as phone-only)? Can one session reach another session\'s secrets or machine?'},
  {key:'app', p:'app/ (Expo + iOS shell app/ios/Shell, interop): does the shell sign exactly what it shows; can the RN side or router text make the phone sign something else; are any secure-page decisions taken outside the shell; can a request be approved without Face ID?'},
  {key:'infra', p:'infra/, k8s/, .github/workflows, policy/: credentials outside the core (Fly org/app tokens, GitHub tokens, S3 keys, Access tokens, setup key) that can achieve a gated effect directly (create/exec machines, read backups and decrypt, push code that changes the core without the visible-commit path, mint deploy keys); CI that could deploy a core change silently.'},
]

phase('Audit')
const minimal = agent(`${CTX}\n\n${REQ}\n\nInventory:\n${invText}\n\nFocus on R2 only: list everything in core/ (state maps, endpoints, branches, parsing, timers, persistence, network calls) that could be moved out or removed while keeping R1. Be concrete with file:line and the smaller design.`, {label:'audit:core-minimal', phase:'Audit', schema: FIND})
  .then(r => ({area:'core-minimal', r}))

const audits = pipeline(AREAS,
  a => agent(`${CTX}\n\n${REQ}\n\nInventory:\n${invText}\n\nAudit area: ${a.p}\nHunt for R1 violations (and R2 where in core/). Only report concrete paths with a file:line and a step-by-step scenario; no generic advice.`, {label:'audit:'+a.key, phase:'Audit', schema: FIND}).then(r => ({area:a.key, r})),
)

const all = [await minimal, ...(await audits)].filter(Boolean)
phase('Verify')
const verified = await pipeline(all.filter(x => x.r && x.r.findings.length),
  x => agent(`${CTX}\n\nYou are a skeptic. For EACH finding below, try hard to REFUTE it by reading the actual code paths end to end (check callers, guards elsewhere, the trust boundary — e.g. a finding that needs the core itself compromised is refuted, one that needs only the router/box is not). Verdict confirmed only if the scenario really works on current main; plausible if it depends on an unverified detail; refuted otherwise.\n\nFindings (${x.area}):\n${JSON.stringify(x.r.findings)}`, {label:'verify:'+x.area, phase:'Verify', schema: VERD})
    .then(v => x.r.findings.map(f => ({...f, area:x.area, ...((v && v.results.find(r => r.title === f.title)) || {verdict:'unverified', reason:''})}))))
const out = verified.filter(Boolean).flat().filter(f => f.verdict !== 'refuted')
log(`${out.length} findings survived verification`)
return { inventoryCount: inv.gated.length, findings: out }
