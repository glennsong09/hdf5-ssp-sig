# Security and safety considerations for Python wrappers around native libraries: the case of h5py and PyTables

The purpose of this model is to provide a practical, threat-modeling-focused overview of the security, safety, and privacy implications of using Python libraries that wrap native code, with a specific focus on **h5py** and **PyTables**. It’s intended for users, maintainers, and security reviewers who want to understand the risks and mitigations in this ecosystem.

## Why native-code wrappers are a special SSP case

When a Python package wraps native code (CPython extension modules, Cython, CFFI/ctypes, or vendored shared libraries), the “Python safety story” largely stops at the boundary where Python hands control to C/C++. From that point on:

- **Memory safety is whatever the native code provides** (plus whatever hardening your toolchain/OS adds).
- **The attack surface expands** to include: native parsers (e.g., HDF5), compression codecs, dynamic loader behavior, plugin systems, and any “convenience” features that serialize/deserialize Python objects.
- **If the native side is compromised, the whole Python process is compromised** (same address space, same privileges, same credentials, same network).

With **h5py** and **PyTables**, you also inherit a large C ecosystem (HDF5 + optional plugins/codecs). PyTables additionally has high-level features (including pickling of Python objects) that can create “code hiding in data” risks that look like pure-Python deserialization bugs.

## Contents

1. [Mental model: what “Python wrapping native code” really means](#mental-model-what-python-wrapping-native-code-really-means)
2. [Security vulnerabilities](#security-vulnerabilities)
3. [Safety vulnerabilities](#safety-vulnerabilities)
4. [Privacy vulnerabilities](#privacy-vulnerabilities)
5. [Mitigation mechanisms available in Python](#mitigation-mechanisms-available-in-python)
6. [The trust boundary: Python interpreter vs. C runtime](#the-trust-boundary-python-interpreter-vs-c-runtime)
7. [Concrete takeaways for h5py and PyTables users](#concrete-takeaways-for-h5py-and-pytables-users)
8. [Why native-code wrappers are a special SSP case](#why-native-code-wrappers-are-a-special-ssp-case)
9. [SSP vulnerability classes mapped to CWE families](#ssp-vulnerability-classes-mapped-to-cwe-families)
10. [Threat model sketches by deployment pattern (h5py vs PyTables)](#threat-model-sketches-by-deployment-pattern-h5py-vs-pytables)
11. [Sources](#sources)

## Mental model: what “Python wrapping native code” really means

With packages like **h5py** and **PyTables**, your process is effectively running a *stack* of trust-sensitive components:

- Your Python application code
- The CPython interpreter (or another Python runtime)
- A C-extension module (compiled glue code)
- The native libraries it links to (e.g., **libhdf5**, compression libraries)
- Optionally, **dynamically loaded plugins** (filters / VFD / VOL connectors), which are native code loaded at runtime

That last point is important: the moment you cross from Python into C, you’re no longer in a memory-safe runtime. There’s no hard sandbox boundary inside the process—only conventions and APIs.

## Security vulnerabilities

These are issues that can be exploited by an attacker to compromise **confidentiality, integrity, or availability** (including code execution).

### 1) Memory-corruption in the native layer (classic “C bugs”)

**Pattern:**

Malformed input (often a file) triggers a bug in the native parser / decoder:

- out-of-bounds read/write
- use-after-free
- integer overflow leading to undersized allocation + overwrite
- null deref (often “only” a crash, sometimes more)

**Why it shows up in h5py/PyTables:**

- Both parse complex on-disk structures through native code paths.
- The Python layer often cannot validate enough to prevent reaching the vulnerable native routine.

**Impact:**

- Worst case: arbitrary code execution in the Python process.
- Best case: denial-of-service via crash.

### 2) “Data file as code loader” (insecure deserialization / embedded executable content)

This is the class CVE-2025-9905 illustrates well: the *file format* (or a “legacy” compatibility path) becomes a vehicle for executing code when “loading data.”

**CVE-style pattern:**

- A loader claims a “safe mode,” but a legacy format path bypasses it.
- A file container (here: `.h5/.hdf5`) includes serialized code artifacts (commonly via `pickle` or equivalents).
- Loading triggers code execution.

**Why it matters for h5py specifically:**

- **h5py** supports storing arbitrary Python objects using **pickle** (e.g., via `ObjectAtom`, and sometimes attributes). That means an HDF5 file can contain pickled payloads that execute on load if your workflow unpickles them (directly or indirectly through higher-level tools).

**Impact:** Straight-line arbitrary code execution when opening or reading content—no native memory corruption required.

### 3) Dynamic native plugin loading (code execution via plugin injection)

**Pattern:**

- Opening a file triggers the native library to load a **plugin** (compression filter, VFD, VOL connector).
- Plugin discovery relies on environment variables / search paths / default directories.
- If an attacker can influence *which* plugin gets loaded (or *where* it’s loaded from), they can execute arbitrary native code.

**Why it’s relevant to h5py/PyTables:**

- They inherit HDF5’s plugin model. Even if your Python code never explicitly loads a plugin, the file’s metadata may cause the library to attempt it.
- Third-party filter ecosystems are common in practice (especially for compression).

**Impact:** Native code execution inside your Python process, under the privileges of the Python process.

### 4) Supply-chain and build-time execution risks (especially for native extensions)

**Pattern:**

- Installing a package that compiles native code (or downloads/builds native components) can execute arbitrary code at build/install time.
- Wheels reduce this risk but don’t eliminate supply-chain compromise risk.

**Impact:** Compromise can happen before you ever import the library.

### 5) “Trust confusion” around file authenticity / provenance

**Pattern:**

- Pipelines treat HDF5 files as inert “data,” but:
  - they may contain pickles
  - they may induce plugin loading
  - they may exploit native parsing bugs
- Integrity checks are missing or optional, so tampering isn’t detectable.

**Impact:** Data poisoning + exploit chaining becomes realistic in ML/science workflows.

## Safety vulnerabilities

Here “safety” means **reliability, correctness, and resilience**: preventing crashes, deadlocks, data corruption, and silent wrong results. These often overlap with security, but the *failure mode* is the focus.

### 1) Process crashes (segfaults/abort) from native faults

**Pattern:**

- A malformed file or edge-case input triggers a fatal crash in native code.
- Even if it’s not exploitable, it kills your whole Python process.

**Typical consequences:**

- Job failures in HPC pipelines
- Service instability in model-serving or data pipelines

### 2) Deadlocks / unsafe concurrency boundaries

**Pattern:**

- Native libraries are not inherently thread-safe (or only in specific build configurations).
- Wrappers introduce global locks to serialize calls, which can interact badly with:
  - background threads
  - garbage collection timing
  - fork + threads

**h5py-specific example:** h5py serializes low-level calls via a global lock; this is good for correctness but can create deadlock hazards in certain thread/GC patterns. PyTables has similar documented threading caveats. (TODO: cite docs!)

### 3) Data corruption from concurrent access patterns

**Pattern:**

- Multiple writers, mixed readers/writers, or multi-process access without correct file locking/SWMR discipline.
- Partial writes + crashes → corrupted files.
- “It worked most of the time” is common and dangerous.

### 4) Denial-of-service by resource exhaustion (even without crashes)

**Pattern:**

- Files specify huge shapes, chunk layouts, deep metadata graphs, or pathological compression behavior.
- Result: explosive CPU, memory usage, or I/O amplification.

**Why it matters:** In scientific/HPC settings, a “valid” file can still be a DoS payload (e.g., extreme chunk fragmentation).

### 5) ABI/version mismatches (subtle misbehavior)

**Pattern:**

- The extension module, NumPy ABI, HDF5 build options, and runtime library versions don’t align.
- Symptoms range from crashes to silent data errors.

## Privacy vulnerabilities

Privacy issues are about **exposing sensitive data or metadata** (sometimes unintentionally, sometimes via malicious behavior).

### 1) Metadata leakage (even when “data” is protected)

**Pattern:**

- HDF5-style containers often store rich metadata:
  - dataset names, shapes, dtypes
  - attributes that may include PII/PHI
- Encrypting payload data alone may still leak sensitive structure.

### 2) Malicious plugin / connector exfiltration

**Pattern:**

- A plugin can observe or transform data in transit:
  - on read: exfiltrate decrypted data
  - on write: siphon or watermark
- If plugins can be injected, privacy is gone.

### 3) Logging / error message leakage

**Pattern:**

Debug logs, exception traces, or telemetry can include:

- filesystem paths
- dataset names
- sample values
- environment configuration

### 4) Unsafe persistence of secrets inside HDF5 artifacts

**Pattern:**

- Storing Python objects (pickled) or configs as attributes can capture:
  - API keys, tokens, credentials
  - internal file paths or user identifiers
- Those artifacts travel with the file.

## Mitigation mechanisms available in Python

Python cannot “make C safe,” but it *can* help you build layered defenses. The most effective approach is usually: **avoid dangerous features + reduce privileges + isolate + monitor + limit resources**.

### A) Prevent the “data becomes code” class

1. **Never unpickle untrusted content**
   - Treat any format/path that uses `pickle` as “code execution on load.”
   - In the PyTables ecosystem, avoid patterns that store arbitrary objects (e.g., object atoms / pickled attributes) when files may cross trust boundaries.

2. **Prefer safe serialization formats**
   - Use JSON / msgpack-like (carefully), Parquet, Arrow, etc., for metadata and objects.
   -For HDF5, store only primitive/array types and explicit structured schemas.

3. **Add authenticity checks before load**
   - If you *must* load serialized objects, require cryptographic provenance:
     - signed artifacts, HMAC, or a trusted signing workflow
   - This doesn’t make pickle “safe,” but it can make it *trust-scoped* (“only load from our signer”).

### B) Control dynamic native plugin loading

1. **Disable plugin loading when you don’t need it**
   - At the native HDF5 layer, plugin loading can be disabled (globally, or by type).
2. **If you need plugins, restrict trust**
   - Only allow plugins from a controlled directory.
   - Prefer signed/verified plugin workflows where available.
   - Make plugin provenance part of your deployment process (not an ad-hoc user environment variable).

### C) Isolate untrusted parsing using processes (your strongest practical boundary)

Because CPython + C extensions share one address space, the best “hard” boundary you can create is **process isolation**:

- Run “open/read/inspect” of untrusted HDF5 in a subprocess
- Apply OS sandboxing/containment to that subprocess (containers, seccomp, AppArmor, low-privilege user)
- Communicate results back via pipes/JSON (not shared memory pointers)

This converts many catastrophic failures:

- RCE → contained to a jailed process (if sandboxed correctly)
- segfault → only kills the worker, not the whole service
- DoS → can be limited and killed

### D) Put hard caps on resource usage (DoS resistance)

In Python you can:

- set **CPU/memory/file limits** on Unix via the `resource` module
- enforce timeouts (signals on Unix, watchdog processes cross-platform)
- kill workers that exceed budgets

This is particularly relevant for:

- pathological chunking / metadata explosions
- decompression bombs
- huge allocation requests implied by file metadata

### E) Runtime monitoring and policy with audit hooks (useful but not a sandbox)

Python’s **audit hooks** can:

- log sensitive operations (dynamic code execution, subprocess creation, loading shared libraries via `ctypes`, etc.)
- optionally block some operations by raising exceptions (with important caveats)

Use audit hooks for:

- detecting unexpected `ctypes` loads
- detecting unexpected subprocess spawns
- detecting unexpected dynamic code execution paths

But be blunt about the limitation:

- a C extension (or a malicious plugin) can often bypass Python-level audit visibility by invoking syscalls directly.

### F) Crash visibility and debugging (safety ops)

- Enable `faulthandler` so that segfaults produce actionable traces
- Treat segfaults as security-relevant events if you process untrusted inputs
- Add fuzzing and sanitizer builds in CI if you maintain native extensions

### 1) The only *real* isolation boundary: a process boundary

If you must open **untrusted** `.h5`/HDF5 inputs, the most effective mitigation is to treat them like you’d treat a PDF from the internet:

* Open/inspect in a **separate process** (or container) with:

  * minimal filesystem access (read-only input, no home dir)
  * no secrets in env vars
  * restricted network egress (ideally none)
  * tight resource limits (CPU, memory, file size, open files)

In Python, that typically means: `subprocess` / `multiprocessing` + OS sandboxing (containers, seccomp, AppArmor/SELinux, job schedulers with cgroups).

### 2) Eliminate “code in data” formats and patterns

* Don’t store/load executable semantics from HDF5 unless you can **cryptographically authenticate** the artifact and you **intend** to run its code.
* Concretely:

  * Prefer safe model/data formats that do not embed executable Python (or treat embedded code as “signed code,” not “data”).
  * For PyTables: avoid `ObjectAtom`/pickle-backed object columns for anything that could come from outside your trust boundary; use JSON, Arrow/Parquet, or application-level schemas.

### 3) Constrain plugin and dynamic loading

Operational controls matter a lot because HDF5 can be steered via environment variables and search paths.

* Defensive posture:

  * **Disable dynamic plugin loading** unless you explicitly need it.
  * If you need plugins: use an **allowlisted directory** with tight permissions, and ensure your runtime ignores user-controlled paths.
  * Treat VOL connectors and filter plugins as part of your **TCB** (trusted computing base).
* Longer-term: signed/verified plugin approaches (where available) are the right direction, but you still need operational guardrails.

### 4) Dependency hygiene (especially for native wheels)

* Pin versions for:

  * Python packages (h5py, tables)
  * native libs they vendor or depend on (HDF5, codecs)
* Use integrity controls in installers (hash checking, internal mirrors).
* In CI: separate “untrusted PR testing” from “trusted release pipelines” (no shared secrets).

### 5) Python runtime monitoring (detection, not a sandbox)

Python provides mechanisms that help you *observe* or sometimes *block* sensitive actions, but they are not a complete sandbox against native code:

* **Audit hooks** (PEP 578) can help detect suspicious activity such as imports, subprocess calls, and some dynamic loading behaviors.
* “Isolated mode” (`python -I`) reduces reliance on user site-packages and environment-driven behavior (helpful in CI and shared machines).
* These help most against *pure Python* abuse; they are weaker once attacker code runs in native space.

### 6) Library-maintainer mitigations (for wrapper authors)

* Compile hardening for extension modules and vendored libs (stack protectors, RELRO, PIE, fortify, etc.).
* Fuzz file parsing surfaces (including filter/plugin paths).
* Defensive parsing: validate sizes/offsets early; cap recursion, allocation sizes, and metadata fanout.
* Make “unsafe” features loud:

  * clear docs, warnings, and safer defaults (e.g., “never auto-unpickle unless explicitly opted in”).

## The trust boundary: Python interpreter vs. C runtime

### The reality: there is no enforced in-process boundary

Inside one Python process:

- C extensions run with the same privileges as Python code
- They can read/write arbitrary memory
- They can perform syscalls, spawn processes, open sockets, bypass Python policy
- A single memory bug can corrupt the interpreter, other extensions, or your application state

So from a threat-model perspective:

- **CPython + all native extensions + all native dependencies + all loadable plugins** are one trust domain.
- If any one of them is compromised, your process is compromised.

### What Python *does* provide at that boundary

- A C-API contract (reference counting, object lifetimes, GIL conventions)
- Some runtime checks in debug builds
- Observability hooks (audit events, faulthandler)

…but none of that is a security sandbox.

### Practical implication for h5py/PyTables

If you process **untrusted files** or run in **multi-tenant environments**, you should assume:

- “Opening a file” can be equivalent to “executing an exploit chain,” via:
  - native parsing vulnerabilities
  - plugin injection
  - pickled object execution paths

Therefore, your *actual* defensible trust boundary is usually:

- **between processes** (subprocess isolation), not between Python and C inside one process.

It’s best to think of the Python↔C boundary like this:

* **It is an ABI boundary, not a security boundary.**
* A C extension (or any dynamically loaded `.so`/`.dll`) executes with:

  * the **same privileges** as the Python process
  * direct access to process memory (including Python objects, secrets)
  * the ability to call OS APIs (files, network, processes)

So, in threat modeling terms:

* Once you import h5py/PyTables (and thereby load native code), you have expanded your **trusted computing base** to include:

  * CPython runtime
  * the wrapper extension modules
  * HDF5 and its dependencies
  * any compression codecs and **any dynamically loaded plugins**
* If you need to treat inputs as hostile, you must enforce the trust boundary **outside the process** (separate process/container/VM).

Also note the “safety→security escalation” reality: many memory-safety bugs start as crashes but become RCE when an attacker controls inputs and the environment is favorable.

## Concrete takeaways for h5py and PyTables users

### If you use h5py

- Treat unknown `.h5` as hostile when it crosses organizational boundaries.
- Prefer subprocess isolation for inspection/transforms of untrusted files.
- Disable or strictly control HDF5 plugin loading unless you have a managed plugin trust story.
- Keep HDF5 and compression dependencies patched and aligned.

### If you use PyTables (and anything built on it, like pandas HDFStore)

- Assume “object dtype” storage may involve **pickle**.
- Avoid designs that store arbitrary Python objects in HDF5 when files may be shared.
- Use safer storage formats/modes (e.g., table-like representations rather than “fixed” object serialization patterns).
- Never load PyTables/pandas HDF artifacts from untrusted sources unless you have strong provenance controls.

## SSP vulnerability classes mapped to CWE families

Below is a practical mapping you can use for threat modeling and reviews. (Many issues cross categories; I’m grouping by the *dominant* failure mode.)

### Safety vulnerabilities (availability + correctness + memory safety)

These are primarily “the process crashes, hangs, corrupts memory, corrupts data, or melts the node/storage.”

**1) Memory corruption in parsers and codecs (native)**
Typical trigger: attacker-controlled file content/metadata causes the native parser to compute a wrong size/offset or follow a malformed pointer-like structure.

- **CWE families**:

  - Out-of-bounds write/read: **CWE-787**, **CWE-125**
  - Use-after-free / double free: **CWE-416**, **CWE-415**
  - Heap/stack overflows: **CWE-122**, **CWE-121**
  - Integer overflow/wraparound: **CWE-190**
  - NULL deref: **CWE-476**

- **Where it shows up for h5py/PyTables**:
  
  Any time you open/parse untrusted HDF5, you’re exercising HDF5’s native parsing logic and any enabled filter/codec code paths.

**2) Resource exhaustion / algorithmic DoS**
Typical trigger: a “valid enough” file that forces pathological allocations or I/O patterns.

- **CWE families**:

  - Uncontrolled resource consumption: **CWE-400**
  - Uncontrolled memory allocation: **CWE-789**
  - Allocation without limits/throttling: **CWE-770**
  - Infinite loop / excessive iteration: **CWE-835**

- **Where it shows up**:

  - Tiny chunking / massive metadata graphs / deep group trees
  - Compression bombs (codec-dependent)
  - “Index building” or table queries that explode CPU/IO in PyTables

**3) Concurrency hazards across the Python↔C boundary**
Typical trigger: native library has global state; wrapper must serialize access; mistakes become corruption or deadlocks.

- **CWE families**:

  - Race condition: **CWE-362**
  - Improper locking: **CWE-667**

- **Where it shows up**:

  - h5py uses an internal global lock to serialize calls into libhdf5; misuse patterns can still deadlock or hurt throughput.
  - PyTables has documented threading guidance to avoid unsafe file-handle sharing across threads.

### Security vulnerabilities (code execution, integrity compromise, privilege misuse)

**1) Unsafe deserialization / “code hiding in data” (the CVE-2025-9905 pattern)**
This is the big one for ecosystems using HDF5 *as a container* for objects that can execute code when loaded.

- **CWE families**:

  - Deserialization of untrusted data: **CWE-502**
  - Improper control of dynamically-managed code resources (the exact CWE used for CVE-2025-9905): **CWE-913**
  - (Often adjacent) Code injection: **CWE-94** / **CWE-95** (when “loading” effectively evaluates code)
 
- **Where it shows up**:

  - **PyTables** explicitly supports storing arbitrary Python objects using pickle (e.g., `ObjectAtom`), which means opening/reading can implicitly deserialize attacker-controlled pickle if you treat the file as “data.”
  - **h5py** itself is more “bytes/arrays focused,” but it is frequently used by higher-level frameworks that embed executable semantics in `.h5` containers (ML model formats, pipelines, etc.). The Keras CVE is a canonical example of this risk.

**2) Untrusted plugin / dynamic library loading (filters, VOL connectors, drivers)**
Any mechanism that causes the process to `dlopen()` a plugin based on file content, environment variables, or search paths is a code execution surface.

- **CWE families**:

  - Inclusion of functionality from an untrusted control sphere / untrusted control of functionality: **CWE-829**
  - Uncontrolled search path element: **CWE-427**
  - Untrusted search path: **CWE-426**
  - External control of system/config setting (env vars): **CWE-15**
  
- **Where it shows up**:

  - HDF5 supports dynamically loaded plugins and can be influenced via environment variables (e.g., plugin preload behavior, VOL connector selection, plugin search paths).
  - In practice: a malicious or trojaned filter/VOL plugin is “just native code in your process.”

**3) Supply-chain / dependency poisoning (wheels, vendored libs, build steps)**
Even if your Python code is safe, your *distribution pipeline* can import compromised native code.

- **CWE families**:

  - Download of code without integrity check: **CWE-494**
  - Inclusion of functionality from untrusted control sphere: **CWE-829** (again, often applies)

- **Where it shows up**:

  - Prebuilt wheels bundling native libs (HDF5, compression libs) and lagging security patches
  - CI pipelines or notebooks installing from mutable indices or unpinned dependencies

**4) Path/control-of-file-name behaviors**
If file metadata can cause the library to open other paths (external links, file nodes, indirect includes), you get unexpected file access.

- **CWE families**:

  - External control of file name or path: **CWE-73**
  - Path traversal: **CWE-22**

- **Where it shows up**:

  - Anything that automatically follows links to other files/locations should be treated as a security boundary crossing (even if it’s “intended functionality”).

### Privacy vulnerabilities (data disclosure, metadata leaks, exfiltration)

**1) Cleartext storage + metadata leakage**
HDF5 often stores rich metadata (names, attributes, shapes, provenance). Even if you encrypt payload arrays at a higher layer, metadata can remain revealing.

* **CWE families**:

  - Cleartext storage of sensitive information: **CWE-312**
  - Exposure of sensitive information: **CWE-200**
  - Exposure of private personal information: **CWE-359** (when applicable)

**2) Sensitive data in logs/errors/core dumps**
Native crashes commonly produce core dumps; Python exceptions can leak paths/identifiers.

* **CWE families**:

  - Information exposure through error message: **CWE-209**
  - Insertion of sensitive info into log file: **CWE-532**

**3) Exfiltration by malicious native code (plugins / deserialization gadgets)**
Once attacker-controlled code executes, privacy loss is typically immediate (credentials, tokens, datasets).

- **CWE families**:

  - Usually modeled as **CWE-829/CWE-502/CWE-913** upstream, with privacy impact captured as **CWE-200/359** consequences.

## h5py vs PyTables: where the risk profile differs (???)

### h5py (typical posture)

- Mostly exposes **HDF5 primitives** (datasets, groups, attrs) and relies on native HDF5 for parsing.
- Biggest SSP risks are therefore:

  1. **Native parsing/codec bugs** (safety → security if exploitable)
  2. **Plugin/dynamic loading surfaces** (security)
  3. **Operational leakage** (privacy)

### PyTables (typical posture)

- Wraps HDF5 but adds higher-level database-like behaviors (tables, querying, indexing), plus features that make it easy to store Python objects.
- Biggest SSP deltas vs h5py:

  1. **Pickle-backed storage of Python objects** is a first-class feature → raises **CWE-502/CWE-913-class risks** if files are treated as untrusted data.
  2. Larger surface area: more extension modules, more optional performance paths, more “magic” behaviors.

A blunt but useful rule in threat modeling:

- **h5py:** “untrusted HDF5 is untrusted native parsing.”
- **PyTables:** “untrusted HDF5 may also be untrusted *Python object graphs*.”

## Threat model sketches by deployment pattern (h5py vs PyTables)

I’ll frame each in terms of **assets**, **attackers**, **primary entry points**, and **top threat scenarios**, and I’ll call out differences between h5py and PyTables.

### 1) HPC cluster (shared filesystem, multi-user, batch jobs)

**Assets:**

- compute allocation, job integrity
- shared parallel filesystem integrity/availability
- research data confidentiality (often large + sensitive)
- any credentials staged into jobs (tokens, SSH keys, object-store creds)

**Attackers:**

- malicious co-tenant user on same cluster
- poisoned dataset/model supplier (public or collaborator)
- compromised shared module/conda environment maintainer
- malicious plugin author (filters/VOL)

**Primary entry points:**

- opening untrusted HDF5 files from shared storage
- environment-controlled plugin/connector selection
- shared library search paths (module files, `LD_LIBRARY_PATH`, etc.)

**Top threat scenarios:**

1. **Data poisoning → Core library exploit**
   Malicious HDF5 triggers memory corruption in native parsing paths (CWE-787/125/416/190).
2. **Data poisoning → Storage DoS**
   Pathological chunking/metadata patterns hammer metadata servers / parallel FS (CWE-400/789/770).
3. **Library poisoning → External library execution**
   Malicious filter/VOL plugin loaded from a writable path (CWE-829/427/15).
4. **Post-execution lateral movement / data theft**
   Compromised job reads other accessible project data or exfiltrates tokens (privacy impact).

**h5py vs PyTables:**

- **h5py:** most risk comes from HDF5 + plugins; simpler high-level surface.
- **PyTables:** same plus higher-level features; if your workflows ever store Python objects (directly or via pandas HDFStore), untrusted files can become **pickle deserialization** risks (CWE-502/913).

**High-leverage mitigations:**

- Run “untrusted file ingest” in a locked-down job/container (no secrets, no network, strict limits).
- Disable/lock down plugin loading unless required; allowlist plugin dirs.
- Avoid PyTables object columns / pickled object storage for shared datasets.

### 2) Shared workstation (multiple users, interactive workflows)

**Assets:**

- user credentials (SSH keys, browser tokens, cloud creds)
- local datasets and configs
- other users’ data if permissions are loose

**Attackers:**

- malicious local user
- malware delivered via files/downloads
- poisoned datasets/models

**Primary entry points:**

- double-click/open workflows (“just load this .h5”)
- environment manipulation (plugin paths, dynamic loader paths)
- user installs packages ad-hoc (pip/conda)

**Top threat scenarios:**

1. **Untrusted model-as-HDF5 → code execution**
   “Looks like data” but loads executable semantics (CWE-913/502 pattern).
2. **DLL/shared-library hijacking via search path**
   Untrusted directories in search paths cause loading attacker code (CWE-427/426).
3. **Crash → data loss/privacy leak via core dumps**
   Sensitive arrays end up in core dumps/logs (CWE-532/209).

**h5py vs PyTables:**

- PyTables’ pickle-backed object storage increases the chance that “opening a file” includes deserialization.

**Mitigations:**

- Treat untrusted HDF5 as hostile; use sandboxing.
- Use isolated Python environments; pin dependencies; minimize ad-hoc installs.

### 3) Cloud notebook (managed Jupyter, shared infra, internet egress)

**Assets:**

- cloud IAM credentials (instance roles, tokens)
- data in object stores
- notebook outputs (often published/shared)

**Attackers:**

- poisoned public datasets/models
- supply-chain attacker (dependency confusion, compromised packages)
- sometimes co-tenant risks depending on platform

**Primary entry points:**

- downloading `.h5` datasets/models and loading them in-notebook
- `pip install` at runtime
- plugins/codecs pulled in for “it won’t read without this filter”

**Top threat scenarios**

1. **Untrusted `.h5` triggers code execution → credential exfiltration**
   High impact because notebooks often have broad data access.
2. **Supply-chain poisoning of native wheels**
   Compromised binary dependency executes at import time (CWE-494/829).
3. **Metadata leakage**
   Paths, dataset names, sample data leak through logs/outputs (CWE-200/532).

**h5py vs PyTables:**

In notebooks, PyTables often appears via pandas; object-dtype persistence can silently introduce pickle semantics.

**Mitigations:**

- No secrets in the same kernel that opens untrusted artifacts.
- Restrict egress; run risky parsing in a separate, least-privileged environment.

### 4) CI runner (ephemeral machines, secrets, untrusted contributions)

**Assets:**

- CI secrets (signing keys, deploy tokens, registry creds)
- build provenance (artifacts, SBOM, release integrity)

**Attackers:**

- malicious PR author
- compromised dependency in build graph

**Primary entry points:**

- test fixtures (malicious `.h5` committed to repo)
- dependency installation steps
- environment variables controlling plugin/dynamic loading

**Top threat scenarios:**

1. **Malicious `.h5` test input triggers native exploit or unsafe deserialization**
   → exfiltrate CI secrets (CWE-787/502/913).
2. **Dependency confusion / poisoned wheel**
   → code execution during install/import (CWE-494/829).
3. **Plugin path tricks**
   → load attacker-controlled plugin shipped in repo (CWE-427/15/829).

**h5py vs PyTables:**

- PyTables + pandas increases the chance of pickle-based persistence pathways appearing in tests.

**Mitigations:**

- Never expose secrets to untrusted PR jobs.
- Pin dependencies + hash-check installs.
- Force a minimal, sanitized environment (and consider `python -I`).
- Run file-parsing tests in a sandboxed job/container with no network.

## Sources

* CVE-2025-9905 details and associated CWE (CWE-913): ([NVD][1])
* PyTables `ObjectAtom` uses pickle “behind the scenes”: ([PyTables][2])
* PyTables VLArray/ObjectAtom pickling note (library reference / source): ([PyTables][3])
* Python `pickle` warning about untrusted data: ([Python documentation][4])
* HDF5 VOL connector environment variable behavior (`HDF5_VOL_CONNECTOR`): ([The HDF Group Support Site][5])
* HDF5 plugin preload control and warning: ([The HDF Group Support Site][6])
* h5py threading + global lock around HDF5 calls: ([h5py][7])
* PyTables threading guidance: ([PyTables][8])
* CASSE threat modeling paper (DML-focused taxonomy + common CWE list):
* HDF5 plugin security via digital signatures (design direction for mitigating untrusted plugins):

[1]: https://nvd.nist.gov/vuln/detail/CVE-2025-9905 "NVD - CVE-2025-9905"
[2]: https://www.pytables.org/usersguide/libref/declarative_classes.html?utm_source=chatgpt.com "Declarative classes — PyTables 3.10.2 documentation"
[3]: https://www.pytables.org/usersguide/libref/homogenous_storage.html?utm_source=chatgpt.com "Homogenous storage classes"
[4]: https://docs.python.org/3/library/pickle.html?utm_source=chatgpt.com "pickle — Python object serialization"
[5]: https://support.hdfgroup.org/documentation/hdf5/latest/group___h5_v_l.html?utm_source=chatgpt.com "VOL connector (H5VL) - HDF5"
[6]: https://support.hdfgroup.org/documentation/hdf5/latest/group___h5_p_l.html?utm_source=chatgpt.com "Dynamically-loaded Plugins (H5PL) - HDF5"
[7]: https://docs.h5py.org/en/latest/threads.html?utm_source=chatgpt.com "Multi-threading — h5py 3.15.1 documentation"
[8]: https://www.pytables.org/cookbook/threading.html?utm_source=chatgpt.com "Threading — PyTables 3.11.0 documentation"

* CVE description and affected/patch details for the Keras `.h5/.hdf5` safe-mode bypass: ([NVD][1])
* PyTables documentation noting that `ObjectAtom` serializes data using `pickle`: ([PyTables][2])
* PyTables documentation noting attributes can store arbitrary Python objects and may automatically use `pickle`: ([PyTables][3])
* pandas documentation warning that PyTables can serialize object-dtype data with `pickle` and that loading from untrusted sources is unsafe: ([Pandas][4])
* Python `pickle` documentation warning that unpickling can execute arbitrary code (and mentioning signing/HMAC as an integrity option): ([Python documentation][5])
* h5py documentation on its global lock and threading model: ([h5py][6])
* HDF5 plugin-control API (`H5PLset_loading_state`) describing how plugin types can be enabled/disabled: ([The HDF Group Support Site][7])
* Python runtime audit hooks (design + usage): ([Python Enhancement Proposals (PEPs)][8])
* Python `resource` module (resource limits via `setrlimit`): ([Python documentation][9])
* Python `faulthandler` module (tracebacks on faults like SIGSEGV): ([Python documentation][10])
* CASSE threat modeling paper for DMLs (vulnerability classes and DML-focused attack framing):
* “Securing HDF5 Plugins with Digital Signatures” (plugin trust, signing/verification approach): 

[1]: https://nvd.nist.gov/vuln/detail/CVE-2025-9905 "NVD - CVE-2025-9905"
[2]: https://www.pytables.org/usersguide/libref/homogenous_storage.html?utm_source=chatgpt.com "Homogenous storage classes"
[3]: https://www.pytables.org/usersguide/libref/file_class.html?utm_source=chatgpt.com "File manipulation class — PyTables 3.10.2 documentation"
[4]: https://pandas.pydata.org/docs/reference/api/pandas.HDFStore.select.html?utm_source=chatgpt.com "pandas.HDFStore.select — pandas 3.0.1 documentation"
[5]: https://docs.python.org/3/library/pickle.html?utm_source=chatgpt.com "pickle — Python object serialization"
[6]: https://docs.h5py.org/en/latest/threads.html?utm_source=chatgpt.com "Multi-threading — h5py 3.15.1 documentation"
[7]: https://support.hdfgroup.org/documentation/hdf5/latest/group___h5_p_l.html?utm_source=chatgpt.com "Dynamically-loaded Plugins (H5PL) - HDF5"
[8]: https://peps.python.org/pep-0578/ "PEP 578 – Python Runtime Audit Hooks | peps.python.org"
[9]: https://docs.python.org/3/library/resource.html?utm_source=chatgpt.com "Resource usage information"
[10]: https://docs.python.org/3/library/faulthandler.html?utm_source=chatgpt.com "faulthandler — Dump the Python traceback"