/**
 * missionBriefings.js — Per-module educational content.
 *
 * Supports two modes:
 *   tutorial — rich walkthrough with theory, concept explanations, and
 *              hand-holding steps. The iframe Lab Browser is active.
 *   lab      — real-pentesting via AttackBox terminal/ZAP. Browser locked.
 *
 * Keyed by module_id.
 */

// Module → vulnerable target path. The Workspace LabBrowser embeds this
// path under /target/ so manual learner activity stays inside the iframe.
export const TARGET_PATH_BY_MODULE = {
  recon:         '/',
  brute_force:   '/auth/login',
  xss:           '/search',
  cmd_injection: '/system/ping?host=127.0.0.1',
  dir_traversal: '/files/read?path=readme.txt',
  file_upload:   '/files/upload',
  csrf:          '/profile/',
}

export function targetPathFor(moduleId) {
  return TARGET_PATH_BY_MODULE[moduleId] || '/'
}

export function targetUrlFor(moduleId, mode = 'tutorial') {
  // Same-origin proxy via the frontend nginx.
  //   tutorial → /target/...      (easy backend; admin:password123 works)
  //   lab      → /target-zap/...  (HARDER backend, reached THROUGH OWASP ZAP so
  //                                every browser request lands in ZAP history —
  //                                like Burp Proxy History. Forwards to
  //                                target-agent/op/... which is the same harder
  //                                backend the old /target-op route served.)
  // Both serve the same Jinja templates so the UI is identical.
  const prefix = mode === 'lab' ? '/target-zap' : '/target'
  return `${prefix}${targetPathFor(moduleId)}`
}

// Required tools displayed in Lab Mode. Local-only — these reference
// the local ATTENSE AttackBox / OWASP ZAP container, never external targets.
export const LAB_REQUIRED_TOOLS = {
  recon:         ['Browser', 'ZAP Proxy History', 'ZAP Inspector', 'ZAP Repeater', 'AttackBox (optional ffuf/curl)'],
  brute_force:   ['ZAP Repeater', 'ZAP Fuzzer', 'AttackBox local wordlist'],
  xss:           ['Browser', 'ZAP Proxy History', 'ZAP Inspector', 'ZAP Repeater', 'ZAP Fuzzer'],
  cmd_injection: ['Browser', 'ZAP Proxy History', 'ZAP Repeater', 'ZAP Fuzzer', 'AttackBox baseline only'],
  dir_traversal: ['Browser', 'ZAP Proxy History', 'ZAP Inspector', 'ZAP Repeater', 'ZAP Fuzzer'],
  file_upload:   ['Browser', 'ZAP Proxy History', 'ZAP Inspector', 'ZAP Repeater', 'ZAP Fuzzer'],
  csrf:          ['Browser', 'ZAP Proxy History', 'ZAP Inspector', 'ZAP Repeater'],
}

// Lab-mode TASKS — TryHackMe-style rich lab manual.
//
// Each entry is a structured task with:
//   - n          : step number
//   - title      : short label
//   - tool       : expected tool (Browser, ZAP Repeater, AttackBox, etc.)
//   - goal       : 1-sentence purpose
//   - command    : AttackBox-only literal command to copy/paste (or commands: [...])
//   - expected   : sample of the expected output that proves success
//   - flags      : optional bullet list of important flag explanations
//   - hint       : optional gotcha
//   - success_marker : the evidence event that fires on success (or human note)
//
// The Workspace renders these as code-block cards, with copy buttons, expected
// output snippets, and a green ✓ next to tasks whose success_marker has fired.
// Lab mode is now objective-based. Completion is determined by backend evidence
// and report quality signals, not by a rigid frontend step checklist.
export const MISSION_BRIEFINGS = {
  recon: {
    background:
      'Reconnaissance is the first phase of any penetration test. Before attempting any exploit, '
      + 'you need to understand what the target is running, which endpoints are exposed, '
      + 'and what technologies are in the stack. This module teaches you to map the attack surface '
      + 'by exploring the target application manually — checking pages, reading HTML source, '
      + 'and discovering hidden routes.',
    objective:
      'Explore the target application to map its attack surface. Visit every page, '
      + 'discover hidden routes, and build a mental map of what the app exposes.',
    watchFor: [
      'The home page reveals 6 internal tools with direct links',
      'HTML comments leak server version: "AcmeCorp-Internal/2.4.1" and "Python/Flask"',
      'robots.txt discloses hidden /admin/, /system/, and /files/ paths',
      'After visiting 4+ areas, a "recon sequence detected" event appears',
    ],
    successCondition: 'Visit 4+ distinct areas and discover a hidden clue.',
    learningGoals: [
      'Understand why reconnaissance is always the first engagement phase',
      'Learn to read HTTP status codes (200, 301, 401, 403, 500)',
      'Identify server technologies from response headers and HTML comments',
      'Build a route map to understand the full attack surface',
    ],
    realWorldImpact:
      'In real-world pentests, recon determines your entire attack strategy. Missing an endpoint '
      + 'means missing a vulnerability. Tools like Nmap, Nikto, and Burp Suite automate this at scale.',
    tip: 'Check the HTML source code of each page — developers often leave sensitive information in comments.',
    // Operator-mode staged hints — ZAP/AttackBox-driven, evidence-based, and
    // kept SEPARATE from the guided tip so guided discovery help never leaks into
    // Operator. Never names the exact hidden route.
    operatorHints: [
      'Hint 1 - Methodology: Treat recon as local application mapping: browse normally first, then replay candidate paths through ZAP so every observation has request/response evidence.',
      'Hint 2 - Where to inspect: Use Proxy History and Inspector to compare 200, 302, and 404 responses under /op/. Hardened discovery files can be useful even when they return 404.',
      'Hint 3 - What to compare: Look at status code, content type, response length, and body text before deciding that a route is real.',
      'Hint 4 - Tool: Use Repeater for individual paths and AttackBox only for validator-safe local ffuf/curl commands against target-agent.',
    ],
  },

  brute_force: {
    background:
      'Credential stuffing and brute force attacks exploit weak, default, or reused passwords. '
      + 'This is one of the most common attack vectors — responsible for over 80% of breaches involving '
      + 'hacking (Verizon DBIR). This lab simulates an endpoint with NO rate limiting, NO account lockout, '
      + 'and NO CAPTCHA — the trifecta of broken authentication. '
      + 'This is OWASP A07:2021 — Identification and Authentication Failures.',
    objective:
      'Discover valid login credentials on the login page by trying different username/password '
      + 'combinations. The endpoint has no rate limit, no lockout, and no CAPTCHA.',
    watchFor: [
      'Distinct error messages: "Incorrect password for admin" vs "Account not found"',
      'No lockout or delay after repeated failures — the form accepts unlimited attempts',
      'A brute-force pattern alert appears after 3+ failures',
      'Successful login redirects to the profile page',
    ],
    successCondition: 'Trigger the brute-force pattern detection and find a valid credential.',
    learningGoals: [
      'Understand how credential stuffing works against web login forms',
      'Learn why rate limiting and account lockout are critical defenses',
      'Recognize username enumeration via distinct error messages',
      'Understand POST form-data authentication flows',
    ],
    realWorldImpact:
      'Tools like Hydra, Burp Intruder, and Medusa automate this at scale. '
      + 'Without rate limiting, an attacker can test thousands of credentials per minute. '
      + 'Defenses: rate limiting, CAPTCHA, MFA, account lockout, bcrypt/scrypt password hashing.',
    // Guided-mode hint (beginner PortSwigger lab): the enumeration + planted
    // credential help is intentional here and appears only in Guided Mode.
    tip: 'admin:password123 is planted in the lab — pay attention to the error messages to confirm the username first.',
    // Operator-mode staged hints (harder lab): ZAP-Workspace-driven, generic
    // errors, evidence-based. NEVER reveals the credential — the answer lives
    // only in the local /lab/operator-passwords.txt seed. Kept SEPARATE from the
    // guided hints above so guided enumeration help never leaks into Operator.
    operatorHints: [
      'Hint 1 - Methodology: Capture one failed login first, then use response differences to guide testing instead of guessing in the browser.',
      'Hint 2 - Where to inspect: In Proxy History, send POST /op/auth/login to Repeater and verify the body fields and generic 401 response.',
      'Hint 3 - What to compare: In Fuzzer results, compare status, length, and redirect behavior; the useful row differs from the repeated failures.',
      'Hint 4 - Tool: Use ZAP Fuzzer for iteration and AttackBox only to print the local lab wordlist for paste-in payloads.',
    ],
  },

  xss: {
    background:
      'Cross-Site Scripting (XSS) is a client-side injection vulnerability where an attacker '
      + 'injects malicious scripts into web pages viewed by other users. Reflected XSS occurs when '
      + 'user input is echoed back in the server response without sanitization. '
      + 'This is OWASP A03:2021 — Injection. XSS can steal cookies, hijack sessions, deface pages, '
      + 'or redirect users to malicious sites. The search endpoint in this lab takes a "q" parameter '
      + 'and renders it directly into the HTML response — no escaping, no CSP.',
    objective:
      'Confirm a reflected Cross-Site Scripting vulnerability on the search page. '
      + 'The search query is rendered unescaped into the HTML response.',
    watchFor: [
      'Your search input appears verbatim in the HTML response — no encoding',
      'HTML tags like <b> actually render as formatted text',
      '<script> tags and event handlers execute or appear unescaped',
      'The Evidence panel shows "XSS-shaped payload submitted" and "Reflected input observed"',
    ],
    successCondition: 'Submit an XSS payload and confirm it reflects unescaped.',
    learningGoals: [
      'Understand reflected vs stored vs DOM-based XSS',
      'Learn common XSS payloads: <script>, event handlers, javascript: URIs',
      'Recognize when input reflection means exploitability',
      'Understand defenses: output encoding, Content Security Policy (CSP), input validation',
    ],
    realWorldImpact:
      'XSS is one of the most prevalent web vulnerabilities. It can steal session cookies, '
      + 'perform actions on behalf of users, and exfiltrate data. '
      + 'Defenses: HTML entity encoding, CSP headers, HttpOnly cookies.',
    tip: 'After submitting a payload, inspect the page source to see exactly how your input was rendered.',
    // Operator-mode staged hints — ZAP-Workspace-driven, evidence-based. Kept
    // separate from the guided tip; never hands over a working payload.
    operatorHints: [
      'Hint 1 - Methodology: Start with a harmless marker, then change only the reflected q parameter after you know where it appears.',
      'Hint 2 - Where to inspect: Use Proxy History, Inspector, and Repeater on GET /op/search?q=... to locate the reflection context in the response body.',
      'Hint 3 - What to compare: Compare whether the marker or proof payload returns encoded, stripped, or preserved as HTML in the response.',
      'Hint 4 - Tool: Put XSS proof payloads in ZAP Repeater/Fuzzer, not AttackBox, because they are HTTP parameter values rather than shell commands.',
    ],
  },

  cmd_injection: {
    background:
      'Command Injection (OS Command Injection) is a CRITICAL vulnerability where an application '
      + 'passes user input directly to system shell commands. The ping diagnostics page in this lab '
      + 'takes a "host" parameter and passes it to os.popen() — with no sanitization whatsoever. '
      + 'This means an attacker can chain additional system commands using shell metacharacters: '
      + '; (semicolon), | (pipe), && (and), $() (subshell), and ` (backtick). '
      + 'This is OWASP A03:2021 — Injection, and typically rated CRITICAL severity.',
    objective:
      'Achieve command injection via the ping diagnostics page. '
      + 'The host input is passed directly to os.popen() with no sanitization.',
    watchFor: [
      'Normal ping output for a clean host value',
      'System command output (uid=, hostname, file contents) after the ping output',
      '"Shell metacharacters observed" appears in the Evidence panel',
      '"Command injection confirmed" fires when uid= or root: appears in output',
    ],
    successCondition: 'Execute a system command via the ping form and see its output.',
    learningGoals: [
      'Understand how shell metacharacters (;, |, &&, $()) enable command chaining',
      'Recognize RCE indicators in HTTP responses (uid, hostname, paths)',
      'Learn why os.popen(), system(), exec() with unsanitized input are dangerous',
      'Understand defenses: input validation, allowlists, parameterized APIs, sandboxing',
    ],
    realWorldImpact:
      'Command injection gives an attacker full control of the server — they can read files, '
      + 'establish persistence, pivot to internal networks, and exfiltrate data. '
      + 'This is how major breaches start. Never pass user input to system commands.',
    tip: 'The ; and && separators are the most reliable. Try reading /etc/passwd first — '
      + 'if you see "root:x:0:0:", injection is confirmed.',
    // Operator-mode staged hints — Repeater/Fuzzer-driven, harmless local proofs
    // only. Kept separate from the guided tip so it never hands over the answer.
    operatorHints: [
      'Hint 1 - Methodology: Establish a clean diagnostics baseline before testing any command-injection proof.',
      'Hint 2 - Where to inspect: Send GET /op/system/ping?host=... to Repeater and modify only the host parameter.',
      'Hint 3 - What to compare: Look for extra local proof output, status changes, or body-length changes after the normal diagnostics output.',
      'Hint 4 - Tool: Use ZAP Repeater/Fuzzer for separator and substitution payloads; AttackBox is only for clean baseline requests.',
    ],
  },

  dir_traversal: {
    background:
      'Directory Traversal (Path Traversal) allows an attacker to escape the intended directory '
      + 'and read arbitrary files on the server. The document viewer page in this lab concatenates '
      + 'the "path" parameter to a base directory without any normalization or sanitization. '
      + 'Using "../" sequences, an attacker can traverse up the directory tree and access system files '
      + 'like /etc/passwd, /etc/shadow, and environment variables. '
      + 'This is OWASP A01:2021 — Broken Access Control.',
    objective:
      'Read arbitrary files on the target server by escaping the web root via '
      + 'the document viewer. No path normalization is applied.',
    watchFor: [
      'The default readme.txt loads normally from the expected directory',
      '"root:x:0:0:root:/root:/bin/bash" appears when reading /etc/passwd',
      'The path field accepts ../ sequences without any filtering',
      '"Sensitive file disclosed" appears in the Evidence panel',
    ],
    successCondition: 'Read /etc/passwd by traversing out of the web root.',
    learningGoals: [
      'Understand how ../ sequences traverse the directory tree',
      'Learn URL encoding tricks: %2e%2e%2f = ../',
      'Recognize sensitive file indicators (/etc/passwd format)',
      'Understand defenses: path canonicalization, chroot, allowlists, os.path.realpath()',
    ],
    realWorldImpact:
      'Path traversal can expose configuration files, credentials, source code, and system info. '
      + 'Combined with other vulnerabilities, it enables full server compromise. '
      + 'Always validate and canonicalize file paths on the server side.',
    tip: '../../etc/passwd is the canonical test path. Each ../ moves one directory up. '
      + 'The base directory is /app/static/, so you need enough ../ to reach /etc/.',
    // Operator-mode staged hints — Repeater/Fuzzer-driven, evidence-based. Kept
    // separate from the guided tip; never names the exact traversal target.
    operatorHints: [
      'Hint 1 - Methodology: Confirm a normal allowed file first, then modify only the file/path parameter.',
      'Hint 2 - Where to inspect: Use Proxy History and Repeater on GET /op/files/read?... and keep the baseline response visible for comparison.',
      'Hint 3 - What to compare: Compare status, length, and body text between an allowed file, a rejected pattern, and a local lab disclosure candidate.',
      'Hint 4 - Tool: Use Repeater or Fuzzer for path variants; do not rely on AttackBox pipelines or output filters.',
    ],
  },

  file_upload: {
    background:
      'Unrestricted file upload is a HIGH severity vulnerability that allows attackers to upload '
      + 'files with dangerous extensions to the server. The upload page in this lab '
      + 'accepts ANY file extension, ANY MIME type, and saves files with the original filename — '
      + 'no validation whatsoever. In a real server with PHP/JSP enabled, this would allow code execution. '
      + 'This is OWASP A04:2021 — Insecure Design.',
    objective:
      'Upload files with dangerous extensions to the upload page. The endpoint accepts any file '
      + 'extension, any MIME type, and saves with the original filename.',
    watchFor: [
      'The upload form accepts any file without checking the extension',
      'Uploaded files are saved with their original filenames',
      'The served URL shows the file is accessible at /static/uploads/',
      '.php, .html, .sh, .js extensions are all accepted',
    ],
    successCondition: 'Upload a file with a dangerous extension (.php, .html, .sh, etc.).',
    learningGoals: [
      'Understand why unrestricted file upload is dangerous on servers with runtime interpreters',
      'Learn why dangerous extensions (.php, .jsp, .sh) matter for web servers',
      'Recognize the danger of serving uploaded files with their original extensions',
      'Understand defenses: extension allowlists, MIME validation, file renaming, separate storage',
    ],
    realWorldImpact:
      'Unrestricted file upload vulnerabilities have led to major breaches. If uploaded files are '
      + 'stored in executable paths, a dangerous extension (.php, .jsp) could enable code execution. '
      + 'In this lab, files are stored but NOT executed. '
      + 'Defenses: extension allowlists, content-type validation, '
      + 'storing files outside the web root, renaming uploads, and scanning with antivirus.',
    tip: 'Try uploading a .html file with <script>alert(1)</script> — it demonstrates stored XSS via file upload.',
    // Operator-mode staged hints — Repeater/Fuzzer-driven, harmless proof files
    // only. Kept separate from the guided tip; never asks for a real web shell.
    operatorHints: [
      'Hint 1 - Methodology: Upload a normal harmless file first so you understand the accepted multipart shape.',
      'Hint 2 - Where to inspect: In Inspector, focus on the multipart filename, file-part Content-Type, and response link.',
      'Hint 3 - What to compare: Change one validation field at a time and compare whether the server rejects, stores, or serves the proof file.',
      'Hint 4 - Tool: Use ZAP Repeater/Fuzzer for multipart edits and keep proof file bodies harmless; do not create a web shell.',
    ],
  },

  csrf: {
    background:
      'Cross-Site Request Forgery (CSRF) tricks an authenticated user into performing actions '
      + 'they did not intend. The profile update endpoint in this lab accepts POST requests '
      + 'without requiring a CSRF token, and does not validate the Origin or Referer headers. '
      + 'This means a malicious page can silently change profile data. '
      + 'This is OWASP A01:2021 — Broken Access Control.',
    objective:
      'Demonstrate that the profile update accepts state-changing requests '
      + 'without CSRF protection by using the built-in attacker lure page.',
    watchFor: [
      'The profile update form has no anti-CSRF token',
      'The lure page contains a hidden form pointing to /profile/update',
      'After clicking the lure button, your email changes silently',
      '"Profile changed without CSRF protection" appears in the Evidence panel',
    ],
    successCondition: 'The profile email is changed by the lure page without any CSRF token.',
    learningGoals: [
      'Understand how CSRF exploits trust between browser and server',
      'Learn the role of CSRF tokens, SameSite cookies, and Origin validation',
      'Recognize state-changing endpoints that lack CSRF protection',
      'Understand defenses: CSRF tokens, SameSite=Strict cookies, Origin/Referer validation',
    ],
    realWorldImpact:
      'CSRF can change passwords, transfer funds, and modify user data without the victim knowing. '
      + 'Modern frameworks (Django, Rails, Spring) include CSRF protection by default, but '
      + 'custom APIs and SPAs often forget it. Always use anti-CSRF tokens for state-changing operations.',
    tip: 'Log in as guest:guest first — the CSRF attack only works when you have an active session.',
    // Operator-mode staged hints — Repeater/Inspector-driven, local lure only.
    // Kept separate from the guided tip; never points at an external exploit host.
    operatorHints: [
      'Hint 1 - Methodology: Identify the normal state-changing profile update before using the local lure.',
      'Hint 2 - Where to inspect: Use Proxy History and Inspector on POST /op/profile/update to check for token fields and session-only trust.',
      'Hint 3 - What to compare: Compare the profile state before and after the local lure submission, and confirm no CSRF token protected the change.',
      'Hint 4 - Tool: Use Browser, Inspector, and Repeater inside the local lab only; do not use external exploit servers or terminal curl chains.',
    ],
  },
}

const TUTORIAL_CONTENT_BY_MODULE = {
  recon: {
    tutorial_steps: [
      {
        title: 'Build the first route map',
        concept:
          'Recon starts by learning what the application intentionally exposes before you test any exploit.',
        why:
          'Most web attacks begin from a normal feature. A login form, search box, file viewer, or admin utility becomes interesting only after you know it exists and what input it accepts.',
        tryIt:
          'Press START, let the Lab Browser open the portal, and list the visible cards: Staff Login, Product Search, Network Diagnostics, Document Viewer, File Upload, and My Profile.',
        lookFor: [
          'Links to /auth/login, /search, /system/ping, /files/read, /files/upload, and /profile/',
          'Feature names that imply sensitive behavior, especially diagnostics and file access',
          'Evidence card: Portal visited',
        ],
        observe:
          'Normal browsing creates route and portal events. Defensive teams use the same pattern to distinguish expected navigation from rapid enumeration.',
      },
      {
        title: 'Inspect source-level hints',
        concept:
          'HTML comments, footer text, and response headers often reveal implementation details that were never meant to guide an attacker.',
        why:
          'Technology disclosure narrows your testing strategy. Knowing that an app uses Flask/Werkzeug changes the payloads, default paths, and error behavior you should investigate.',
        tryIt:
          'Open the portal page source or browser inspector. Read comments and footer text before clicking away.',
        lookFor: [
          'Server: AcmeCorp-Internal/2.4.1',
          'Framework: Python/Flask',
          'Build and host hints such as 2024-Q3-internal or acme-web-01',
        ],
        observe:
          'Evidence may not fire for every visual clue. Treat source notes as manual findings and correlate them with route-discovery events.',
      },
      {
        title: 'Touch each feature area',
        concept:
          'Attack surface mapping means visiting each reachable feature and noting the parameters, forms, and state changes it exposes.',
        why:
          'A route with query parameters, file paths, upload fields, or profile updates is a direct test target.',
        tryIt:
          'Click each portal card. Identify q on Search, host on Ping, path on Document Viewer, file on Upload, and email on Profile.',
        lookFor: [
          'GET parameters visible in the address bar',
          'Forms that submit POST requests',
          'Evidence cards for search_used, diagnostics_used, file_viewer_used, file_upload_used, or route_discovered',
        ],
        observe:
          'The platform raises a recon sequence event after enough distinct areas are visited. In production, that same signal can indicate probing.',
      },
      {
        title: 'Check common hidden files',
        concept:
          'Robots and well-known files are not access controls. They are public hints that can accidentally reveal internal paths and contacts.',
        why:
          'Attackers often check /robots.txt and /.well-known/security.txt because these files are easy to request and frequently mention sensitive routes.',
        tryIt:
          'Use the Lab Browser address bar to visit /target/robots.txt and /target/.well-known/security.txt, then click CHECK PROGRESS.',
        lookFor: [
          'Disallow entries for /admin/, /system/, /files/, or /backup/',
          'Internal contact addresses and policy URLs',
          'Evidence cards: Hidden clue accessed and Recon sequence detected',
        ],
        observe:
          'A hidden-clue evidence event is a defensive indicator that someone is looking beyond normal application navigation.',
      },
    ],
    defenseBreakdown: {
      title: 'Reduce information disclosure and detect enumeration',
      summary:
        'Recon cannot be eliminated, but applications should avoid giving attackers a clean route map and should alert on unusual discovery behavior.',
      mitigations: [
        {
          name: 'Remove production debug hints',
          implementation:
            'Strip framework, build, and host comments from HTML templates. Keep internal build metadata in deployment tooling, not page source.',
          verify:
            'Review rendered HTML and HTTP headers for framework names, version strings, internal hostnames, and environment names.',
        },
        {
          name: 'Harden public metadata files',
          implementation:
            'Keep robots.txt minimal and never list sensitive paths as a secrecy mechanism. Publish security.txt only with intended public contact information.',
          verify:
            'Request /robots.txt and /.well-known/security.txt from an unauthenticated session and confirm they do not expose private route structure.',
        },
        {
          name: 'Monitor enumeration patterns',
          implementation:
            'Alert on high route cardinality, repeated 404s, access to hidden metadata, and rapid transitions across unrelated application areas.',
          verify:
            'Replay a browsing sequence and confirm SIEM rules group the activity into a reconnaissance alert.',
        },
      ],
    },
  },

  brute_force: {
    tutorial_steps: [
      {
        title: 'Read the login behavior first',
        concept:
          'Broken authentication is not only about weak passwords. The way a login form responds can leak usernames and make guessing easier.',
        why:
          'A secure login should avoid revealing whether the username or password was wrong, and it should slow repeated attempts.',
        tryIt:
          'Open /target/auth/login. Submit admin with a deliberately wrong password such as wrongpass.',
        lookFor: [
          'Error message: Incorrect password for admin',
          'HTTP 401 behavior after a failed login',
          'Evidence card: Failed login observed',
        ],
        observe:
          'A defender should see failed login events with username, source IP, and timestamp. Repeated failures are the beginning of the brute-force signal.',
      },
      {
        title: 'Confirm username enumeration',
        concept:
          'Username enumeration happens when the app gives different responses for valid and invalid account names.',
        why:
          'Attackers can split the problem in half: first find real users, then test passwords only against those accounts.',
        tryIt:
          'Submit fakeuser with any password. Compare the message with the admin failure from the previous step.',
        lookFor: [
          'Account not found for invalid usernames',
          'Incorrect password for known usernames',
          'Same endpoint, different information leak',
        ],
        observe:
          'Evidence captures the failed login either way, but the application response leaks which usernames are worth attacking.',
      },
      {
        title: 'Test common credentials manually',
        concept:
          'A manual brute-force test uses a small, realistic password set before using tools.',
        why:
          'Manual testing shows whether any rate limit, delay, CAPTCHA, or lockout exists.',
        tryIt:
          'Try admin/password, admin/123456, admin/admin, admin/password123, guest/guest, and operator/lab2024.',
        lookFor: [
          'The form accepts repeated attempts without delay',
          'No CAPTCHA, lockout banner, or cool-down timer',
          'Evidence card: Brute-force pattern detected after multiple failures',
        ],
        observe:
          'Three or more failures in a short window create the brute-force pattern event. In a SOC, this would become a threshold or anomaly rule.',
      },
      {
        title: 'Confirm the valid credential',
        concept:
          'A credential is confirmed only when it produces authenticated behavior, not merely a different error.',
        why:
          'False positives happen. The proof is a successful login, redirect, session cookie, or access to a protected page.',
        tryIt:
          'Log in with admin/password123. If the browser lands on the profile page, the credential is valid.',
        lookFor: [
          'Redirect to /profile/',
          'Profile details visible after authentication',
          'Evidence cards: Successful login observed and Valid credential confirmed',
        ],
        observe:
          'A failure-to-success sequence from one IP is a high-value detection. It often means credential guessing worked.',
      },
    ],
    defenseBreakdown: {
      title: 'Make guessing expensive and low-signal',
      summary:
        'The vulnerable login leaks user validity and permits unlimited attempts. Fix both the response behavior and the rate of attempts.',
      mitigations: [
        {
          name: 'Generic authentication errors',
          implementation:
            'Return the same message and status behavior for unknown users and wrong passwords, such as "Invalid username or password."',
          verify:
            'Submit a known user and an unknown user with the same bad password and confirm response body, timing, and status are indistinguishable.',
        },
        {
          name: 'Rate limiting and lockout',
          implementation:
            'Apply per-account and per-IP throttles, progressive delays, and temporary lockouts after repeated failures. Store counters server-side.',
          verify:
            'Run repeated failed attempts and confirm the app slows or blocks further attempts while logging the event.',
        },
        {
          name: 'MFA and credential monitoring',
          implementation:
            'Require MFA for privileged accounts and alert on failure bursts, password-spray patterns, and failure-to-success transitions.',
          verify:
            'Test a guessed password against a protected account and confirm MFA blocks access and generates a high-priority alert.',
        },
      ],
    },
  },

  xss: {
    tutorial_steps: [
      {
        title: 'Find the reflection point',
        concept:
          'Reflected XSS starts with user input that comes back in the response immediately.',
        why:
          'Reflection is not automatically exploitable, but it tells you where browser-controlled content enters the page.',
        tryIt:
          'Open Search and submit a harmless query such as hello-attenselab.',
        lookFor: [
          'Your exact text appears under Search Results',
          'The URL contains q= with your query',
          'Evidence card: Search feature used',
        ],
        observe:
          'The Evidence panel confirms endpoint use. The browser output tells you whether the input is reflected.',
      },
      {
        title: 'Test whether HTML is encoded',
        concept:
          'Output encoding converts characters such as < and > into harmless entities before the browser parses them as markup.',
        why:
          'If the app renders tags as real HTML, script execution is usually one payload away.',
        tryIt:
          'Search for <b>bold</b>. If the word appears bold instead of showing literal angle brackets, the output context is unsafe.',
        lookFor: [
          'Formatted bold text in the result area',
          'No visible escaping such as &lt;b&gt;',
          'The same input value still present in the search box',
        ],
        observe:
          'This step may not trigger XSS evidence yet, but it proves the result slot treats input as HTML.',
      },
      {
        title: 'Submit script and event payloads',
        concept:
          'A reflected XSS payload asks the victim browser to execute attacker-supplied JavaScript in the vulnerable site origin.',
        why:
          'Script execution can read page content, make authenticated requests, deface UI, or steal non-HttpOnly data.',
        tryIt:
          'Search for <script>alert(1)</script>, then try <img src=x onerror=alert(1)> and <svg onload=alert(1)>.',
        lookFor: [
          'An alert box or unescaped payload in the rendered output/source',
          'Event-handler attributes preserved',
          'Evidence cards: XSS-shaped payload submitted and Reflected input observed',
        ],
        observe:
          'Multiple payload styles help defenders separate accidental angle brackets from deliberate exploitation attempts.',
      },
      {
        title: 'Tie exploitability to defenses',
        concept:
          'The fix is contextual output encoding first, with CSP as a second layer.',
        why:
          'Input filtering alone is brittle because attackers can switch HTML, attribute, URL, and JavaScript contexts.',
        tryIt:
          'Click CHECK PROGRESS after at least one payload reflects. Review which evidence cards fired.',
        lookFor: [
          'Unsafe reflection rather than only payload submission',
          'No Content Security Policy blocking inline scripts',
          'No template auto-escaping in the vulnerable result slot',
        ],
        observe:
          'A defensive finding should describe both the vulnerable sink and the missing control: unescaped HTML rendering plus no meaningful CSP.',
      },
    ],
    defenseBreakdown: {
      title: 'Encode output and constrain script execution',
      summary:
        'The search page renders q as trusted HTML. The primary fix is contextual encoding at render time, supported by browser-side containment.',
      mitigations: [
        {
          name: 'Contextual output encoding',
          implementation:
            'Render user-controlled text through the template engine auto-escape path. In HTML body context, encode &, <, >, ", and \'.',
          verify:
            'Search for <b>test</b> and confirm the page displays literal tags or entities rather than formatted HTML.',
        },
        {
          name: 'Content Security Policy',
          implementation:
            'Set a CSP such as script-src \'self\' with nonces for approved scripts and no unsafe-inline. Treat CSP as defense in depth, not the main fix.',
          verify:
            'Submit <script>alert(1)</script> and confirm both that it is encoded and that inline script execution would be blocked.',
        },
        {
          name: 'Safe templating patterns',
          implementation:
            'Ban raw/safe rendering for untrusted values. Add review checks for Jinja |safe, dangerouslySetInnerHTML, and equivalent APIs.',
          verify:
            'Search the codebase for unsafe rendering APIs and require tests that assert encoded output for user input.',
        },
      ],
    },
  },

  cmd_injection: {
    tutorial_steps: [
      {
        title: 'Establish normal command behavior',
        concept:
          'Command injection testing starts by understanding what system command the feature appears to run.',
        why:
          'The diagnostics page looks like a wrapper around ping. If user input is concatenated into a shell command, shell metacharacters can change the command.',
        tryIt:
          'Open Network Diagnostics, enter 127.0.0.1, and run the ping.',
        lookFor: [
          'Normal ping output in the response area',
          'Host value mirrored into the command output',
          'Evidence card: Diagnostics form used',
        ],
        observe:
          'Normal use establishes a baseline. Defenders need this baseline to separate diagnostics from injection attempts.',
      },
      {
        title: 'Probe shell separators',
        concept:
          'Shells treat characters such as ;, &&, |, backticks, and $() as command-control syntax.',
        why:
          'If the application passes input to a shell, these characters can append or substitute commands.',
        tryIt:
          'Enter 127.0.0.1; id and run it. Then try 127.0.0.1 && whoami.',
        lookFor: [
          'Output containing uid=, user names, host names, or Linux details',
          'Evidence card: Shell metacharacters observed',
          'A response that includes more than ping output',
        ],
        observe:
          'Even a failed separator attempt is useful evidence. It shows someone tested shell syntax against a parameter.',
      },
      {
        title: 'Confirm with file disclosure',
        concept:
          'A proof of command injection should show attacker-chosen command output, not just an error.',
        why:
          'Reading a known local file proves the server executed your injected command in its own environment.',
        tryIt:
          'Enter 127.0.0.1; cat /etc/passwd. If the shell accepts it, the output should include account-like lines.',
        lookFor: [
          'root:x:0:0:root or /bin/bash in the response',
          'Evidence card: Command injection confirmed',
          'The original ping output plus extra command output',
        ],
        observe:
          'The detection looks for command-output indicators such as uid=, root:, /bin/, /etc/, and Linux strings.',
      },
      {
        title: 'Define the defensive boundary',
        concept:
          'The safe design is to avoid shell interpretation entirely.',
        why:
          'Input validation helps, but shell parsing is too complex to secure with string replacement.',
        tryIt:
          'Try 127.0.0.1 | whoami, 127.0.0.1 && id, and 127.0.0.1$(id), then click CHECK PROGRESS.',
        lookFor: [
          'Different metacharacters producing similar command execution',
          'Repeated command separator evidence',
          'No server-side allowlist limiting host input to IPs or DNS names',
        ],
        observe:
          'Defensive triage should treat confirmed command injection as critical because it can become full server compromise.',
      },
    ],
    defenseBreakdown: {
      title: 'Remove shell interpretation from user input',
      summary:
        'The ping feature builds a shell command with the host parameter. Replace string-built shell execution with safe process APIs and strict validation.',
      mitigations: [
        {
          name: 'Use subprocess without a shell',
          implementation:
            'Call ping with an argument list, for example subprocess.run(["ping", "-c", "2", host], shell=False), and never concatenate a command string.',
          verify:
            'Submit 127.0.0.1; id and confirm it is treated as an invalid host, not as a second command.',
        },
        {
          name: 'Allowlist host input',
          implementation:
            'Accept only valid IP addresses or DNS names using a parser such as ipaddress for IPs and a conservative hostname regex for names.',
          verify:
            'Confirm inputs containing spaces, semicolons, pipes, backticks, $, parentheses, and slashes are rejected before execution.',
        },
        {
          name: 'Least privilege and containment',
          implementation:
            'Run diagnostics under a low-privilege account inside a restricted container with no secrets mounted and limited network reach.',
          verify:
            'Even if a command runs, confirm it cannot read sensitive files or reach internal-only networks outside the lab boundary.',
        },
      ],
    },
  },

  dir_traversal: {
    tutorial_steps: [
      {
        title: 'Understand the intended file root',
        concept:
          'File viewers should restrict users to a controlled document directory.',
        why:
          'If the application simply joins a base path and user input, ../ segments can escape the intended directory.',
        tryIt:
          'Open the Document Viewer. Keep the default path readme.txt and click Read File.',
        lookFor: [
          'The readme content loads normally',
          'The path parameter appears in the URL as path=readme.txt',
          'Evidence card: File viewer used',
        ],
        observe:
          'Normal access creates baseline evidence. The interesting question is whether the path field is constrained to the document directory.',
      },
      {
        title: 'Move up the directory tree',
        concept:
          '../ means parent directory. Repeating it can climb from the application document root toward system directories.',
        why:
          'The server file open call resolves those path segments. Without canonicalization and boundary checks, user input controls the final file path.',
        tryIt:
          'Replace readme.txt with ../../etc/passwd and submit the form. Add more ../ segments if needed.',
        lookFor: [
          'Evidence card: Path traversal observed',
          'An error that reveals the resolved path, or sensitive content if the traversal reaches the file',
          'The path value preserved in the input field',
        ],
        observe:
          'Traversal evidence fires when ../, encoded dot-dot, /etc, /proc, passwd, or shadow-like input appears.',
      },
      {
        title: 'Confirm sensitive file disclosure',
        concept:
          'A sensitive file disclosure is confirmed by recognizable file content, not by the payload alone.',
        why:
          '/etc/passwd is a common proof because it is often readable and has a predictable root:x:0:0 format.',
        tryIt:
          'Continue adjusting the traversal depth until the output includes root:x:0:0.',
        lookFor: [
          'root:x:0:0:root',
          'daemon, bin, nobody, or /bin/bash entries',
          'Evidence card: Sensitive file disclosed',
        ],
        observe:
          'The platform marks sensitive disclosure when the response body contains known system-file indicators.',
      },
      {
        title: 'Try encoded variants',
        concept:
          'Traversal filters often block literal ../ but miss encoded or equivalent forms.',
        why:
          'Servers, proxies, and frameworks can decode paths at different layers. A robust defense must normalize before validation.',
        tryIt:
          'Try URL-encoded variants such as ..%2f..%2fetc%2fpasswd, then click CHECK PROGRESS.',
        lookFor: [
          'Encoded dot-dot sequences still reaching traversal detection',
          'Errors that disclose the server filesystem layout',
          'Traversal pattern followed by sensitive disclosure',
        ],
        observe:
          'Encoded traversal attempts are strong evidence of deliberate testing and should be logged even when blocked.',
      },
    ],
    defenseBreakdown: {
      title: 'Canonicalize paths and enforce a base-directory boundary',
      summary:
        'The file viewer trusts a raw path parameter. Fix it by resolving the final path and proving it remains inside the intended directory before opening it.',
      mitigations: [
        {
          name: 'Resolve then validate',
          implementation:
            'Use pathlib.Path(base, user_path).resolve() or os.path.realpath, then reject the request unless the resolved path is within the allowed base directory.',
          verify:
            'Submit ../../etc/passwd and confirm the app returns a generic forbidden response without disclosing the resolved filesystem path.',
        },
        {
          name: 'Use file identifiers',
          implementation:
            'Expose document IDs or slugs mapped server-side to known files instead of accepting arbitrary path strings from users.',
          verify:
            'Confirm requests for unknown IDs fail without ever passing user input into open().',
        },
        {
          name: 'Reduce filesystem blast radius',
          implementation:
            'Run the app in a container with minimal readable files, no secrets in environment variables, and read permissions scoped to required content.',
          verify:
            'Attempt to read /etc/passwd, /proc/self/environ, and application config paths and confirm sensitive data is unavailable.',
        },
      ],
    },
  },

  file_upload: {
    tutorial_steps: [
      {
        title: 'Upload a harmless baseline file',
        concept:
          'File upload testing starts with normal behavior: what the form accepts, where the file is stored, and how it is served back.',
        why:
          'The baseline reveals storage paths, URL structure, filename handling, and whether uploads are publicly reachable.',
        tryIt:
          'Open File Upload. Choose a small .txt file and submit it.',
        lookFor: [
          'Success message showing a server save path',
          'An Open link under /static/uploads/',
          'Evidence cards: File upload form used and File saved on the server',
        ],
        observe:
          'Defenders should log upload metadata: filename, content type, size, source IP, user, and storage destination.',
      },
      {
        title: 'Check filename preservation',
        concept:
          'Keeping the original filename can preserve dangerous extensions, overwrite names, or expose user-supplied content directly.',
        why:
          'A secure upload pipeline usually renames files to random IDs and stores metadata separately.',
        tryIt:
          'Upload a file with a unique name such as attenselab-proof.txt. Confirm the served URL keeps that exact name.',
        lookFor: [
          'Original filename in the storage path',
          'Public link that includes the original extension',
          'No randomized server-side filename',
        ],
        observe:
          'Filename preservation is not always a vulnerability by itself, but it raises risk when combined with executable or browser-rendered extensions.',
      },
      {
        title: 'Submit a dangerous extension',
        concept:
          'Dangerous extensions are file types that a web server, browser, or downstream tool may execute or interpret.',
        why:
          'If uploads are served from an executable path, extensions such as .php, .jsp, .sh, .html, .svg, and .js can lead to code execution or stored XSS.',
        tryIt:
          'Create a file named proof.php or proof.html. For HTML, use <script>alert(1)</script> as content. Upload it through the form.',
        lookFor: [
          'The upload succeeds instead of rejecting the extension',
          'Evidence card: Dangerous extension accepted',
          'Evidence card: Unrestricted upload confirmed',
        ],
        observe:
          'This lab stores files but does not execute PHP. The finding is still valid: the application accepts and serves risky file types without policy checks.',
      },
      {
        title: 'Inspect MIME and storage risk',
        concept:
          'MIME type and extension can both be faked by clients. Secure systems inspect content and enforce an allowlist.',
        why:
          'Relying only on browser-provided Content-Type lets attackers label executable content as harmless.',
        tryIt:
          'Upload content that does not match its extension, then click the served upload link and CHECK PROGRESS.',
        lookFor: [
          'No content validation warning',
          'Uploads served from /static/uploads/',
          'No antivirus, allowlist, quarantine, or size policy',
        ],
        observe:
          'A defender should treat dangerous uploads as high severity, especially when files are web-accessible and keep attacker-controlled names.',
      },
    ],
    defenseBreakdown: {
      title: 'Treat uploads as untrusted content',
      summary:
        'The upload endpoint accepts any filename, extension, and content type. A secure pipeline validates, renames, stores, scans, and serves files safely.',
      mitigations: [
        {
          name: 'Extension and content allowlist',
          implementation:
            'Allow only business-required types, validate file signatures with server-side inspection, and reject mismatches between extension, MIME, and magic bytes.',
          verify:
            'Upload .php, .html, .svg, and renamed script content and confirm each is rejected unless explicitly allowed for the feature.',
        },
        {
          name: 'Randomized names and isolated storage',
          implementation:
            'Store files outside executable web roots using generated names. Serve downloads through an authorization endpoint or object-storage signed URL.',
          verify:
            'Confirm the public URL never contains the original filename and that uploaded files cannot be executed by the application server.',
        },
        {
          name: 'Scanning and operational limits',
          implementation:
            'Apply size limits, malware scanning, quarantine, audit logging, and per-user upload quotas.',
          verify:
            'Test oversize files, known test signatures, and repeated uploads to ensure controls reject and log appropriately.',
        },
      ],
    },
  },

  csrf: {
    tutorial_steps: [
      {
        title: 'Start with an authenticated session',
        concept:
          'CSRF abuses the browser session a victim already has with a trusted site.',
        why:
          'If the user is not authenticated, there is no useful session cookie for the attacker to ride.',
        tryIt:
          'Open /target/auth/login and sign in with guest/guest or admin/password123. Then open /target/profile/.',
        lookFor: [
          'Profile page showing username, role, and email address',
          'Email update form that submits to /profile/update',
          'A session-backed profile page before the attack',
        ],
        observe:
          'The important asset is the session cookie. The attacker does not need to know it; the browser attaches it automatically to same-site requests.',
      },
      {
        title: 'Inspect the missing token',
        concept:
          'A CSRF token is an unpredictable value tied to the user session and included in legitimate state-changing forms.',
        why:
          'An attacker page can create a form, but it cannot know a per-session secret token if the application checks one correctly.',
        tryIt:
          'Look at the profile update form. Search for hidden inputs named csrf, _csrf_token, token, or similar.',
        lookFor: [
          'No hidden CSRF token field',
          'Only an email input and submit button',
          'A POST action to /profile/update',
        ],
        observe:
          'Missing-token evidence appears when the update endpoint receives a POST without a CSRF token field.',
      },
      {
        title: 'Visit and submit the attacker lure',
        concept:
          'A CSRF attack can be disguised as a normal button or page on another route.',
        why:
          'The victim clicks something harmless-looking, but the browser submits a hidden form to the vulnerable application.',
        tryIt:
          'Open /target/evil/csrf-demo, click Claim my reward, then return to /target/profile/.',
        lookFor: [
          'A simulated reward page',
          'Email changed to hacked@evil.lab',
          'Evidence cards: Attacker lure page visited and Profile changed without CSRF protection',
        ],
        observe:
          'The most important evidence is state change without a token. This proves impact, not just missing markup.',
      },
      {
        title: 'Map the defense layers',
        concept:
          'CSRF defenses combine request tokens, cookie policy, and request-origin validation.',
        why:
          'Tokens prove the form came from the application, SameSite reduces cross-site cookie sending, and Origin/Referer checks catch many forged browser requests.',
        tryIt:
          'Click CHECK PROGRESS and compare csrf_lure_visited, csrf_token_missing, and profile_changed_without_csrf.',
        lookFor: [
          'Forged form submission after visiting the lure page',
          'State change recorded with no token',
          'No Origin or Referer enforcement blocking the update',
        ],
        observe:
          'In a real incident, a profile change from an unusual Referer or missing token should be investigated as account abuse.',
      },
    ],
    defenseBreakdown: {
      title: 'Require proof of user intent for state-changing requests',
      summary:
        'The profile update trusts only the session cookie. Add anti-CSRF tokens and browser cookie protections so forged forms cannot mutate state.',
      mitigations: [
        {
          name: 'Synchronizer or double-submit CSRF tokens',
          implementation:
            'Generate an unpredictable token per session or request, render it into every state-changing form, and validate it server-side before processing.',
          verify:
            'Submit /profile/update without the token and confirm the server returns 403 and does not change the email.',
        },
        {
          name: 'SameSite cookie policy',
          implementation:
            'Set session cookies with SameSite=Lax or Strict, Secure, and HttpOnly. Use Strict for highly sensitive applications when workflow allows it.',
          verify:
            'Attempt a cross-site form POST from a separate origin and confirm the browser does not attach the session cookie when policy should block it.',
        },
        {
          name: 'Origin and Referer validation',
          implementation:
            'For state-changing requests, require Origin or Referer to match the expected site origin. Treat this as a backup to tokens, not a replacement.',
          verify:
            'Replay a POST with missing or foreign Origin/Referer and confirm it is rejected and logged.',
        },
      ],
    },
  },
}

for (const [moduleId, content] of Object.entries(TUTORIAL_CONTENT_BY_MODULE)) {
  if (MISSION_BRIEFINGS[moduleId]) {
    delete MISSION_BRIEFINGS[moduleId].steps
    MISSION_BRIEFINGS[moduleId].tutorial_steps = content.tutorial_steps
    MISSION_BRIEFINGS[moduleId].defenseBreakdown = content.defenseBreakdown
  }
}

export const DEFAULT_BRIEFING = {
  background: 'This module demonstrates a vulnerability in the target application.',
  objective: 'Explore the vulnerable page and discover the security flaw.',
  target_path: '/',
  tutorial_steps: [
    {
      title: 'Explore the target page',
      concept: 'Start with normal application behavior before testing payloads.',
      why: 'The baseline tells you what changed when a vulnerability is triggered.',
      tryIt: 'Open the Lab Browser, interact with the page, and identify user-controlled inputs.',
      lookFor: ['Forms', 'Query parameters', 'Evidence cards'],
      observe: 'Use the Evidence panel to connect your action to the platform detection.',
    },
    {
      title: 'Test the likely weak point',
      concept: 'Most web vulnerabilities appear where user input reaches a sensitive sink.',
      why: 'Input fields, file paths, shell commands, and state-changing forms all need server-side controls.',
      tryIt: 'Submit one careful test payload and compare the response with your baseline.',
      lookFor: ['Unexpected output', 'Errors', 'Detection events'],
      observe: 'A successful test should produce both visible behavior and an evidence card.',
    },
  ],
  watchFor: ['Activity in the Evidence panel', 'Detection alerts in the feed'],
  successCondition: 'Mission objectives completed via manual interaction.',
  learningGoals: ['Understand the vulnerability', 'Observe detection indicators'],
  realWorldImpact: 'This vulnerability is exploited in real-world penetration tests.',
  tip: null,
  defenseBreakdown: {
    title: 'Validate, contain, and monitor',
    summary: 'Apply server-side controls at the trust boundary and alert on suspicious usage.',
    mitigations: [
      {
        name: 'Server-side validation',
        implementation: 'Validate untrusted input before it reaches sensitive code paths.',
        verify: 'Submit malformed input and confirm it is rejected and logged.',
      },
    ],
  },
}

export function briefingFor(moduleId) {
  return MISSION_BRIEFINGS[moduleId] || DEFAULT_BRIEFING
}

// ── Mode-aware accessors ────────────────────────────────────────────────────

/** Tutorial mode: return the walkthrough steps from the briefing. */
export function tutorialStepsFor(moduleId) {
  const b = MISSION_BRIEFINGS[moduleId] || DEFAULT_BRIEFING
  return b.tutorial_steps || b.steps || []
}

/** Lab mode: return the rich structured Operator Mode task objects. */
export function requiredToolsFor(moduleId) {
  return LAB_REQUIRED_TOOLS[moduleId] || ['Browser', 'ZAP Repeater', 'ZAP Fuzzer', 'AttackBox (safe commands only)']
}

/** Return the objective text for lab mode. */
export function labObjectiveFor(moduleId) {
  const b = MISSION_BRIEFINGS[moduleId] || DEFAULT_BRIEFING
  if (b.lab_objective) return b.lab_objective
  const base = b.objective || b.background || ''
  return base
    ? `Lab brief — ${base} Use the local Browser, ZAP tools, and validator-safe AttackBox commands only where the brief labels them.`
    : 'Use the local Browser, ZAP tools, and validator-safe AttackBox commands only where the brief labels them.'
}
