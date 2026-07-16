const ALLOWED_ORIGINS = new Set([
  "https://mrbrands.store",
  "https://www.mrbrands.store"
]);

const MAX_HTML_BYTES = 1500000;
const MAX_AUX_BYTES = 500000;
const PAGE_TIMEOUT_MS = 12000;
const PAGESPEED_TIMEOUT_MS = 25000;

export default {
  async fetch(request, env) {
    const requestUrl = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (requestUrl.pathname === "/tool" && request.method === "GET") {
      return mrbrandsToolResponse();
    }

    if (requestUrl.pathname === "/" && request.method === "GET") {
      return jsonResponse({
        ok: true,
        service: "MrBrands Instant Page Readiness Score",
        version: "4.0.1",
        endpoint: "/audit",
        categories: 9,
        note: "Worker-hosted scoring interface available at /tool. Full site health, search coverage and Growth Unit workload require the verified audit."
      }, 200, origin);
    }

    if (requestUrl.pathname !== "/audit") {
      return jsonResponse({ ok: false, error: "Not found." }, 404, origin);
    }

    if (!["GET", "POST"].includes(request.method)) {
      return jsonResponse({ ok: false, error: "Method not allowed." }, 405, origin);
    }

    const isSameWorkerOrigin = origin === requestUrl.origin;

    if (origin && !isSameWorkerOrigin && !ALLOWED_ORIGINS.has(origin)) {
      return jsonResponse({ ok: false, error: "Origin not allowed." }, 403, origin);
    }

    try {
      let rawUrl = "";

      if (request.method === "GET") {
        rawUrl = requestUrl.searchParams.get("url") || "";
      } else {
        const contentType = request.headers.get("content-type") || "";
        if (contentType.includes("application/json")) {
          const payload = await request.json();
          rawUrl = payload && payload.url ? String(payload.url) : "";
        } else {
          const form = await request.formData();
          rawUrl = String(form.get("url") || "");
        }
      }

      const target = normaliseTargetUrl(rawUrl);
      validatePublicTarget(target);

      const primary = await fetchHtml(target);
      const originUrl = new URL(primary.finalUrl.origin + "/");

      const supportResults = await Promise.allSettled([
        primary.finalUrl.pathname === "/" ? Promise.resolve(primary) : fetchHtml(originUrl, MAX_AUX_BYTES),
        fetchText(new URL("/robots.txt", originUrl), MAX_AUX_BYTES),
        fetchSitemap(originUrl),
        fetchPageSpeed(primary.finalUrl, env)
      ]);

      const homepage = fulfilledValue(supportResults[0]);
      const robots = fulfilledValue(supportResults[1]);
      const sitemap = fulfilledValue(supportResults[2]);
      const pagespeed = fulfilledValue(supportResults[3]);

      const result = analyseAudit({
        primary,
        homepage,
        robots,
        sitemap,
        pagespeed
      });

      return jsonResponse({
        ok: true,
        requestedUrl: target.href,
        finalUrl: primary.finalUrl.href,
        fetchedAt: new Date().toISOString(),
        result
      }, 200, origin);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unexpected audit error.";
      return jsonResponse({ ok: false, error: message }, 400, origin);
    }
  }
};

function fulfilledValue(result) {
  return result && result.status === "fulfilled" ? result.value : null;
}

function corsHeaders(origin) {
  const workerOriginPattern = /^https:\/\/mrbrands-readiness-tool-v4\.[a-z0-9-]+\.workers\.dev$/i;
  const allowed = ALLOWED_ORIGINS.has(origin) || workerOriginPattern.test(origin)
    ? origin
    : "https://mrbrands.store";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function jsonResponse(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Cache-Control": "no-store",
      ...corsHeaders(origin)
    }
  });
}

function normaliseTargetUrl(raw) {
  let value = String(raw || "").trim();
  if (!value) throw new Error("Enter a public website address.");
  if (!/^https?:\/\//i.test(value)) value = "https://" + value;

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("The website address is not valid.");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS webpages can be audited.");
  }

  parsed.hash = "";
  parsed.username = "";
  parsed.password = "";
  return parsed;
}

function validatePublicTarget(url) {
  const host = url.hostname.toLowerCase();

  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host === "0.0.0.0" ||
    host === "::1" ||
    host === "169.254.169.254" ||
    host === "metadata.google.internal"
  ) {
    throw new Error("Only public websites can be audited.");
  }

  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b, c, d] = ipv4.slice(1).map(Number);
    if ([a, b, c, d].some(n => n > 255)) throw new Error("Invalid IP address.");

    if (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    ) {
      throw new Error("Only public websites can be audited.");
    }
  }

  if (host.includes(":")) {
    const clean = host.replace(/^\[|\]$/g, "").toLowerCase();
    if (
      clean === "::1" ||
      clean === "::" ||
      clean.startsWith("fc") ||
      clean.startsWith("fd") ||
      /^fe[89ab]/.test(clean)
    ) {
      throw new Error("Only public websites can be audited.");
    }
  }
}

async function fetchHtml(initialUrl, maxBytes = MAX_HTML_BYTES) {
  let current = new URL(initialUrl.href);

  for (let redirects = 0; redirects <= 3; redirects++) {
    validatePublicTarget(current);

    const response = await timedFetch(current.href, {
      method: "GET",
      redirect: "manual",
      headers: {
        "User-Agent": "MrBrandsGrowthReadiness/2.0 (+https://mrbrands.store/)",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"
      }
    }, PAGE_TIMEOUT_MS);

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) throw new Error("The website returned an invalid redirect.");
      current = new URL(location, current);
      continue;
    }

    const type = (response.headers.get("content-type") || "").toLowerCase();
    if (!type.includes("text/html") && !type.includes("application/xhtml+xml")) {
      throw new Error("The address did not return an HTML webpage.");
    }

    const declared = Number(response.headers.get("content-length") || "0");
    if (declared > maxBytes) throw new Error("The webpage is too large for the instant audit.");

    const html = await response.text();
    const bytes = new TextEncoder().encode(html).byteLength;
    if (bytes > maxBytes) throw new Error("The webpage is too large for the instant audit.");

    return {
      html,
      finalUrl: current,
      status: response.status,
      bytes,
      contentType: type
    };
  }

  throw new Error("The website redirected too many times.");
}

async function fetchText(url, maxBytes = MAX_AUX_BYTES) {
  validatePublicTarget(url);

  const response = await timedFetch(url.href, {
    method: "GET",
    redirect: "follow",
    headers: {
      "User-Agent": "MrBrandsGrowthReadiness/2.0 (+https://mrbrands.store/)",
      "Accept": "text/plain,text/xml,application/xml,*/*;q=0.1"
    }
  }, PAGE_TIMEOUT_MS);

  if (!response.ok) {
    return { ok: false, status: response.status, url: url.href, text: "" };
  }

  const text = await response.text();
  const bytes = new TextEncoder().encode(text).byteLength;
  if (bytes > maxBytes) {
    return { ok: false, status: 413, url: url.href, text: "" };
  }

  return { ok: true, status: response.status, url: url.href, text };
}

async function fetchSitemap(originUrl) {
  const robots = await fetchText(new URL("/robots.txt", originUrl), MAX_AUX_BYTES);
  let sitemapUrl = null;

  if (robots.ok) {
    const match = robots.text.match(/^\s*Sitemap:\s*(\S+)\s*$/im);
    if (match) {
      try {
        sitemapUrl = new URL(match[1], originUrl);
      } catch {}
    }
  }

  if (!sitemapUrl) sitemapUrl = new URL("/sitemap.xml", originUrl);
  const sitemap = await fetchText(sitemapUrl, MAX_AUX_BYTES);

  return {
    ok: sitemap.ok && /<(?:urlset|sitemapindex)\b/i.test(sitemap.text),
    status: sitemap.status,
    url: sitemap.url,
    type: /<sitemapindex\b/i.test(sitemap.text) ? "index" :
      /<urlset\b/i.test(sitemap.text) ? "urlset" : "unknown",
    urlCountHint: countMatches(sitemap.text, /<loc>/gi)
  };
}

async function fetchPageSpeed(url, env) {
  const api = new URL("https://www.googleapis.com/pagespeedonline/v5/runPagespeed");
  api.searchParams.set("url", url.href);
  api.searchParams.set("strategy", "mobile");
  ["PERFORMANCE", "ACCESSIBILITY", "BEST_PRACTICES", "SEO"].forEach(category => {
    api.searchParams.append("category", category);
  });
  if (env && env.PAGESPEED_API_KEY) {
    api.searchParams.set("key", env.PAGESPEED_API_KEY);
  }

  try {
    const response = await timedFetch(api.href, { method: "GET" }, PAGESPEED_TIMEOUT_MS);
    if (!response.ok) {
      return { available: false, error: `PageSpeed returned HTTP ${response.status}` };
    }

    const data = await response.json();
    const categories = data.lighthouseResult && data.lighthouseResult.categories
      ? data.lighthouseResult.categories
      : {};
    const audits = data.lighthouseResult && data.lighthouseResult.audits
      ? data.lighthouseResult.audits
      : {};

    const performance = score100(categories.performance && categories.performance.score);
    const accessibility = score100(categories.accessibility && categories.accessibility.score);
    const bestPractices = score100(categories["best-practices"] && categories["best-practices"].score);
    const seo = score100(categories.seo && categories.seo.score);

    const field = data.loadingExperience && data.loadingExperience.overall_category
      ? data.loadingExperience.overall_category
      : "UNKNOWN";

    return {
      available: true,
      strategy: "mobile",
      performance,
      accessibility,
      bestPractices,
      seo,
      fieldCategory: field,
      metrics: {
        lcpMs: numericAudit(audits, "largest-contentful-paint"),
        cls: numericAudit(audits, "cumulative-layout-shift"),
        tbtMs: numericAudit(audits, "total-blocking-time"),
        speedIndexMs: numericAudit(audits, "speed-index")
      }
    };
  } catch (error) {
    return {
      available: false,
      error: error instanceof Error ? error.message : "PageSpeed unavailable"
    };
  }
}

async function timedFetch(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (error) {
    if (error && error.name === "AbortError") {
      throw new Error("A website check took too long to respond.");
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function score100(value) {
  return typeof value === "number" ? Math.round(value * 100) : null;
}

function numericAudit(audits, key) {
  const audit = audits && audits[key];
  return audit && typeof audit.numericValue === "number"
    ? Math.round(audit.numericValue * 100) / 100
    : null;
}

function analyseAudit(context) {
  const { primary, homepage, robots, sitemap, pagespeed } = context;
  const html = primary.html;
  const pageUrl = primary.finalUrl;

  const visible = visibleText(html);
  const lower = visible.toLowerCase();
  const firstText = lower.slice(0, 1400);
  const title = decode(firstMatch(html, /<title\b[^>]*>([\s\S]*?)<\/title>/i));
  const description = extractMeta(html, "description");
  const robotsMeta = extractMeta(html, "robots").toLowerCase();
  const canonical = extractLink(html, "canonical");
  const viewport = Boolean(extractMeta(html, "viewport"));
  const h1 = extractTags(html, "h1");
  const h2 = extractTags(html, "h2");
  const h3 = extractTags(html, "h3");
  const summaries = extractTags(html, "summary");
  const paragraphs = extractTags(html, "p");
  const links = extractAnchors(html, pageUrl);
  const internalLinks = links.filter(item => item.internal);
  const descriptiveAnchorRatio = anchorQualityRatio(links.filter(item => item.internal));
  const images = countMatches(html, /<img\b[^>]*>/gi);
  const imagesWithAlt = countMatches(html, /<img\b(?=[^>]*\balt\s*=\s*["'][^"']+["'])[^>]*>/gi);
  const altCoverage = images ? imagesWithAlt / images : 1;
  const schema = extractJsonLd(html);
  const schemaLower = schema.toLowerCase();
  const wordCount = countWords(visible);
  const detailsCount = countMatches(html, /<details\b/gi);
  const listCount = countMatches(html, /<(?:ul|ol)\b/gi);
  const tableCount = countMatches(html, /<table\b/gi);
  const formCount = countMatches(html, /<form\b/gi);
  const buttonCount = countMatches(html, /<button\b/gi) +
    countMatches(html, /class\s*=\s*["'][^"']*(?:btn|button)[^"']*["']/gi);
  const phoneCount = countMatches(html, /href\s*=\s*["']tel:/gi);
  const emailCount = countMatches(html, /href\s*=\s*["']mailto:/gi);
  const questionHeadings = [...h2, ...h3, ...summaries]
    .filter(value => /\?$/.test(value.trim())).length;
  const conciseAnswers = paragraphs.filter(value => {
    const words = countWords(value);
    return words >= 25 && words <= 90;
  }).length;
  const placeholderContent = /lorem ipsum|coming soon|under construction|placeholder/i.test(visible);
  const jsShellLikely = wordCount < 180 && html.length > 25000 &&
    countMatches(html, /<script\b/gi) > 8;

  const homepageHtml = homepage && homepage.html ? homepage.html : "";
  const homepageLinks = homepageHtml ? extractAnchors(homepageHtml, new URL(primary.finalUrl.origin + "/")) : [];
  const homepageInternal = homepageLinks.filter(item => item.internal);

  const location = inferLocation(pageUrl, title, h1);
  const locationHits = location ? countPhraseOccurrences(lower, location.toLowerCase()) : 0;
  const localTarget = Boolean(location);
  const firstHeading = h1[0] || "";

  const categories = {};
  const allChecks = [];

  const technical = [];
  addCheck(technical, {
    id: "http_success",
    label: "Successful page response",
    passed: primary.status >= 200 && primary.status < 400,
    points: 2,
    severity: "critical",
    success: "The page returned a successful response.",
    fail: `The page returned HTTP ${primary.status}.`,
    action: "Fix server, redirect or availability errors before content work."
  });
  addCheck(technical, {
    id: "https",
    label: "HTTPS security",
    passed: pageUrl.protocol === "https:",
    points: 1,
    severity: "high",
    success: "The page uses HTTPS.",
    fail: "The page is not using HTTPS.",
    action: "Move the website to a valid HTTPS connection."
  });
  addCheck(technical, {
    id: "indexable",
    label: "Indexability",
    passed: !robotsMeta.includes("noindex"),
    points: 2,
    severity: "critical",
    success: "No noindex instruction was detected.",
    fail: "The page contains a noindex instruction.",
    action: "Remove unintended noindex directives and verify canonical/indexing settings."
  });
  addCheck(technical, {
    id: "canonical",
    label: "Canonical URL",
    passed: Boolean(canonical),
    points: 1,
    severity: "high",
    success: "A canonical URL is declared.",
    fail: "No canonical URL was detected.",
    action: "Add a self-referencing or otherwise appropriate canonical URL."
  });
  addCheck(technical, {
    id: "viewport",
    label: "Mobile viewport",
    passed: viewport,
    points: 1,
    severity: "high",
    success: "A mobile viewport is declared.",
    fail: "The mobile viewport declaration is missing.",
    action: "Add a responsive viewport and verify the page on mobile devices."
  });
  addCheck(technical, {
    id: "robots_file",
    label: "Robots file",
    passed: Boolean(robots && robots.ok),
    points: 1,
    severity: "medium",
    success: "robots.txt is accessible.",
    fail: "robots.txt was not accessible.",
    action: "Publish and review robots.txt so important content is not blocked."
  });
  addCheck(technical, {
    id: "sitemap",
    label: "XML sitemap",
    passed: Boolean(sitemap && sitemap.ok),
    points: 1,
    severity: "medium",
    success: "An XML sitemap was found.",
    fail: "No valid XML sitemap was found.",
    action: "Publish an XML sitemap and submit it in Google Search Console."
  });
  addCheck(technical, {
    id: "single_h1",
    label: "Single primary H1",
    passed: h1.length === 1,
    points: 2,
    severity: "high",
    success: "Exactly one H1 was found.",
    fail: `${h1.length} H1 elements were found.`,
    action: "Use one clear primary H1 and move secondary headings to H2 or styled text."
  });
  addCheck(technical, {
    id: "html_content",
    label: "Accessible HTML content",
    passed: !jsShellLikely,
    points: 1,
    severity: "high",
    success: "Substantial content is available in the returned HTML.",
    fail: "The returned HTML appears to contain very little visible content.",
    action: "Ensure important content is server-rendered or reliably available to crawlers."
  });
  categories.technical = createCategory("Technical access & indexability", 12, technical);

  const metadata = [];
  addCheck(metadata, {
    id: "title",
    label: "Page title",
    passed: title.length >= 25 && title.length <= 65,
    points: 3,
    severity: "high",
    success: "The page title is present and within a useful range.",
    fail: "The page title is missing or outside the useful range.",
    action: "Write a concise title that clearly describes the page and search intent."
  });
  addCheck(metadata, {
    id: "description",
    label: "Meta description",
    passed: description.length >= 100 && description.length <= 170,
    points: 2,
    severity: "medium",
    success: "A useful meta description is present.",
    fail: "The meta description is missing or poorly sized.",
    action: "Write a persuasive page-specific description for search snippets."
  });
  addCheck(metadata, {
    id: "title_h1_alignment",
    label: "Title and H1 alignment",
    passed: semanticOverlap(title, firstHeading) >= 0.35,
    points: 1,
    severity: "medium",
    success: "The title and H1 describe a consistent topic.",
    fail: "The title and H1 do not appear closely aligned.",
    action: "Align the title and H1 around the same primary purpose."
  });
  addCheck(metadata, {
    id: "h2_structure",
    label: "Section-heading structure",
    passed: h2.length >= 3 && h2.length <= 20,
    points: 1,
    severity: "medium",
    success: "The page has a useful H2 structure.",
    fail: "The H2 structure appears weak or excessive.",
    action: "Organise the page into clear customer-led sections."
  });
  addCheck(metadata, {
    id: "heading_order",
    label: "Heading hierarchy",
    passed: headingHierarchyReasonable(html),
    points: 1,
    severity: "medium",
    success: "The heading hierarchy appears logical.",
    fail: "The heading hierarchy contains likely skipped or excessive levels.",
    action: "Use headings in a logical H1, H2 and H3 hierarchy."
  });
  addCheck(metadata, {
    id: "image_alt",
    label: "Image alternative text",
    passed: altCoverage >= 0.8,
    points: 1,
    severity: "medium",
    success: "Most images include alternative text.",
    fail: "Too many images are missing useful alternative text.",
    action: "Add concise, accurate alt text to meaningful images."
  });
  addCheck(metadata, {
    id: "open_graph",
    label: "Social sharing metadata",
    passed: /<meta\b[^>]*(?:property|name)\s*=\s*["']og:title["']/i.test(html),
    points: 1,
    severity: "low",
    success: "Open Graph metadata is present.",
    fail: "Open Graph sharing metadata was not detected.",
    action: "Add social sharing titles, descriptions and images."
  });
  categories.metadata = createCategory("Metadata & SERP presentation", 10, metadata);

  const performance = [];
  if (pagespeed && pagespeed.available) {
    addMetric(performance, {
      id: "mobile_performance",
      label: "Mobile performance",
      value: pagespeed.performance,
      points: 4,
      severity: "high",
      bands: [
        { min: 90, fraction: 1, success: "Mobile Lighthouse performance is strong." },
        { min: 75, fraction: 0.75, success: "Mobile Lighthouse performance is reasonable." },
        { min: 50, fraction: 0.45, success: "Mobile Lighthouse performance needs improvement." },
        { min: 0, fraction: 0.15, success: "Mobile Lighthouse performance is weak." }
      ],
      fail: "Mobile performance is weak.",
      action: "Reduce blocking scripts, oversized assets and rendering delays."
    });
    addMetric(performance, {
      id: "field_cwv",
      label: "Core Web Vitals field status",
      value: pagespeed.fieldCategory,
      points: 3,
      severity: "high",
      bands: [
        { equals: "FAST", fraction: 1, success: "Field performance is classified as fast." },
        { equals: "AVERAGE", fraction: 0.55, success: "Field performance needs some improvement." },
        { equals: "SLOW", fraction: 0.15, success: "Field performance is slow." },
        { equals: "UNKNOWN", fraction: 0.5, success: "No sufficient field data was available." }
      ],
      fail: "Core Web Vitals field data is weak.",
      action: "Improve LCP, CLS and interaction performance on real mobile visits."
    });
    addMetric(performance, {
      id: "best_practices",
      label: "Lighthouse best practices",
      value: pagespeed.bestPractices,
      points: 1,
      severity: "medium",
      bands: scoreBands(),
      fail: "Lighthouse best-practice checks need improvement.",
      action: "Resolve browser, security and implementation best-practice warnings."
    });
    addMetric(performance, {
      id: "accessibility",
      label: "Lighthouse accessibility",
      value: pagespeed.accessibility,
      points: 1,
      severity: "medium",
      bands: scoreBands(),
      fail: "Accessibility checks need improvement.",
      action: "Improve contrast, labels, semantics and keyboard usability."
    });
    addMetric(performance, {
      id: "lighthouse_seo",
      label: "Lighthouse SEO",
      value: pagespeed.seo,
      points: 1,
      severity: "medium",
      bands: scoreBands(),
      fail: "Lighthouse SEO checks need improvement.",
      action: "Resolve the technical SEO issues reported by Lighthouse."
    });
  } else {
    addMetric(performance, {
      id: "pagespeed_unavailable",
      label: "PageSpeed coverage",
      value: null,
      points: 10,
      severity: "medium",
      fixedFraction: 0.5,
      success: "PageSpeed data was unavailable, so a neutral provisional score was used.",
      fail: "PageSpeed data was unavailable.",
      action: "Run mobile and desktop PageSpeed checks in the verified audit."
    });
  }
  categories.performance = createCategory("Performance & mobile experience", 10, performance);

  const content = [];
  addCheck(content, {
    id: "content_depth",
    label: "Visible content depth",
    passed: wordCount >= 650,
    points: 3,
    severity: "high",
    success: "The page contains substantial visible content.",
    fail: `Only about ${wordCount} visible words were detected.`,
    action: "Expand the page with useful service, process, proof and customer-decision content."
  });
  addCheck(content, {
    id: "topic_first_screen",
    label: "Clear topic near the top",
    passed: topicClarity(firstText, title, h1),
    points: 2,
    severity: "high",
    success: "The page purpose is clear near the top.",
    fail: "The page purpose is not clear enough near the top.",
    action: "State what the business offers, who it helps and the next step early."
  });
  addCheck(content, {
    id: "customer_language",
    label: "Customer-decision language",
    passed: hasAny(lower, ["cost", "price", "process", "how it works", "suitable", "included", "what you get", "compare", "choose"]),
    points: 2,
    severity: "medium",
    success: "The page addresses customer decisions.",
    fail: "Important buying questions are not addressed clearly.",
    action: "Add cost, process, suitability, comparison and expectation content."
  });
  addCheck(content, {
    id: "specifics",
    label: "Specific business facts",
    passed: hasSpecificFacts(visible),
    points: 2,
    severity: "medium",
    success: "The page includes specific facts, quantities or named deliverables.",
    fail: "The wording appears broad and lacks specific supporting facts.",
    action: "Add concrete services, deliverables, timeframes, examples and limitations."
  });
  addCheck(content, {
    id: "evidence_content",
    label: "Evidence-led content",
    passed: evidenceSignals(html, lower) >= 2,
    points: 2,
    severity: "high",
    success: "Multiple evidence signals are present.",
    fail: "The page contains limited evidence supporting its claims.",
    action: "Add relevant cases, reviews, examples, qualifications or measurable proof."
  });
  addCheck(content, {
    id: "placeholder",
    label: "Complete published content",
    passed: !placeholderContent,
    points: 1,
    severity: "high",
    success: "No obvious placeholder content was found.",
    fail: "Placeholder or unfinished wording was detected.",
    action: "Replace unfinished or placeholder content before promotion."
  });
  addCheck(content, {
    id: "readable_sections",
    label: "Readable page sections",
    passed: paragraphs.length >= 6 && h2.length >= 3,
    points: 2,
    severity: "medium",
    success: "The page is divided into useful readable sections.",
    fail: "The page needs clearer sections and supporting paragraphs.",
    action: "Break the content into concise sections around customer questions."
  });
  categories.content = createCategory("Content quality & intent match", 14, content);

  const architecture = [];
  addCheck(architecture, {
    id: "internal_links",
    label: "Internal-link coverage",
    passed: internalLinks.length >= 10,
    points: 2,
    severity: "high",
    success: "The page has useful internal links.",
    fail: `Only ${internalLinks.length} internal links were detected.`,
    action: "Connect the page to relevant services, locations, guides, proof and enquiry routes."
  });
  addCheck(architecture, {
    id: "anchor_quality",
    label: "Descriptive anchor text",
    passed: descriptiveAnchorRatio >= 0.7,
    points: 2,
    severity: "medium",
    success: "Most internal links use descriptive anchor text.",
    fail: "Too many internal links use weak or generic anchor text.",
    action: "Replace generic anchors with concise descriptions of the destination."
  });
  addCheck(architecture, {
    id: "breadcrumb",
    label: "Breadcrumb support",
    passed: schemaLower.includes("breadcrumblist") || /breadcrumb/i.test(html),
    points: 1,
    severity: "low",
    success: "Breadcrumb support was detected.",
    fail: "No breadcrumb support was detected.",
    action: "Add visible or structured breadcrumbs where useful."
  });
  addCheck(architecture, {
    id: "sitemap_architecture",
    label: "Sitemap discovery",
    passed: Boolean(sitemap && sitemap.ok),
    points: 2,
    severity: "medium",
    success: "The website exposes an XML sitemap.",
    fail: "The website does not expose a valid XML sitemap.",
    action: "Create and maintain a complete XML sitemap."
  });
  addCheck(architecture, {
    id: "homepage_navigation",
    label: "Homepage navigation depth",
    passed: homepageInternal.length >= 8,
    points: 1,
    severity: "medium",
    success: "The homepage links to a useful range of internal destinations.",
    fail: "The homepage appears to expose too few internal destinations.",
    action: "Strengthen navigation to important services, locations, proof and guides."
  });
  addCheck(architecture, {
    id: "supporting_routes",
    label: "Supporting page relationships",
    passed: supportingRouteCount(links) >= 3,
    points: 2,
    severity: "high",
    success: "The page links to several supporting routes.",
    fail: "The page appears isolated from supporting content and conversion routes.",
    action: "Build a connected service, location, guide, proof and conversion structure."
  });
  categories.architecture = createCategory("Architecture & internal discovery", 10, architecture);

  const commercial = [];
  if (localTarget) {
    addCheck(commercial, {
      id: "location_title",
      label: "Location in title or H1",
      passed: includesPhrase(title + " " + firstHeading, location),
      points: 2,
      severity: "high",
      success: "The target location appears in the title or H1.",
      fail: "The target location is missing from the title and H1.",
      action: "Clarify the genuine local service target in the title and primary heading."
    });
    addCheck(commercial, {
      id: "location_depth",
      label: "Meaningful local relevance",
      passed: locationHits >= 6,
      points: 2,
      severity: "high",
      success: "The page uses the location with meaningful depth.",
      fail: "The location appears too rarely to establish strong relevance.",
      action: "Add genuine local sectors, customer needs, service detail and regional context."
    });
    addCheck(commercial, {
      id: "area_schema",
      label: "Area-served clarity",
      passed: schemaLower.includes("areaserved"),
      points: 2,
      severity: "medium",
      success: "Area-served structured data is present.",
      fail: "Area-served structured data was not detected.",
      action: "Add accurate area-served information without implying a false office."
    });
    addCheck(commercial, {
      id: "coverage_copy",
      label: "Coverage and delivery wording",
      passed: hasAny(lower, ["serving", "coverage", "area", "remote", "nationwide", "local", "nearby"]),
      points: 2,
      severity: "medium",
      success: "Coverage and delivery information is visible.",
      fail: "Coverage and delivery expectations are unclear.",
      action: "Explain genuine service coverage and how the work is delivered."
    });
    addCheck(commercial, {
      id: "regional_context",
      label: "Regional or nearby context",
      passed: hasAny(lower, ["nearby", "region", "county", "connected markets", "surrounding"]),
      points: 1,
      severity: "low",
      success: "Regional or nearby context is present.",
      fail: "The page contains little wider geographic context.",
      action: "Add relevant county, regional or nearby-market relationships."
    });
    addCheck(commercial, {
      id: "commercial_route",
      label: "Commercial next step",
      passed: hasAny(lower, ["package", "pricing", "quote", "enquiry", "contact", "request"]),
      points: 1,
      severity: "high",
      success: "A commercial next step is visible.",
      fail: "The page does not make the next commercial step clear.",
      action: "Add an appropriate enquiry, package, booking or quotation route."
    });
  } else {
    addCheck(commercial, {
      id: "audience",
      label: "Target customer clarity",
      passed: hasAny(lower, ["businesses", "customers", "clients", "homeowners", "companies", "teams", "retailers"]),
      points: 2,
      severity: "high",
      success: "The target customer is clear.",
      fail: "The intended customer is unclear.",
      action: "State who the service is for and the problem it solves."
    });
    addCheck(commercial, {
      id: "service",
      label: "Service or product clarity",
      passed: hasAny(lower, ["service", "product", "package", "solution", "system", "programme"]),
      points: 2,
      severity: "high",
      success: "The offer is described clearly.",
      fail: "The offer is not described clearly enough.",
      action: "Clarify the service, deliverables and outcomes."
    });
    addCheck(commercial, {
      id: "coverage",
      label: "Market or coverage clarity",
      passed: hasAny(lower, ["uk", "nationwide", "local", "online", "remote", "serving", "delivery"]),
      points: 2,
      severity: "medium",
      success: "Market or delivery coverage is visible.",
      fail: "Market and delivery coverage are unclear.",
      action: "Explain where and how the business serves customers."
    });
    addCheck(commercial, {
      id: "contact",
      label: "Contact clarity",
      passed: hasAny(lower, ["contact", "email", "phone", "call", "enquiry"]),
      points: 2,
      severity: "medium",
      success: "A contact route is visible.",
      fail: "The contact route is unclear.",
      action: "Make contact details and enquiry routes easy to find."
    });
    addCheck(commercial, {
      id: "offer_route",
      label: "Offer or pricing route",
      passed: hasAny(lower, ["package", "pricing", "price", "quote", "book", "buy", "request"]),
      points: 2,
      severity: "high",
      success: "A clear offer route is present.",
      fail: "The commercial offer route is unclear.",
      action: "Add packages, pricing guidance, quotation or booking routes."
    });
  }
  categories.commercial = createCategory(
    localTarget ? "Local relevance & commercial intent" : "Market relevance & commercial intent",
    10,
    commercial
  );

  const aeo = [];
  addCheck(aeo, {
    id: "direct_answer_top",
    label: "Direct answer near the top",
    passed: hasAny(firstText, ["direct answer", "what is", "what does", "we help", "we provide", "this service"]),
    points: 2,
    severity: "high",
    success: "A direct explanatory answer appears near the top.",
    fail: "The opening does not provide a concise direct answer.",
    action: "Add a short answer explaining the service, audience and outcome near the top."
  });
  addCheck(aeo, {
    id: "questions",
    label: "Question-led sections",
    passed: questionHeadings >= 3,
    points: 2,
    severity: "high",
    success: "Several customer questions are used as headings.",
    fail: "Too few customer questions are used as visible headings.",
    action: "Add question-led sections around cost, process, suitability and comparisons."
  });
  addCheck(aeo, {
    id: "faq_content",
    label: "FAQ content",
    passed: detailsCount >= 3 || hasAny(lower, ["frequently asked questions", "faq"]),
    points: 2,
    severity: "medium",
    success: "Substantial FAQ content is present.",
    fail: "FAQ content is limited or missing.",
    action: "Add useful FAQs based on real customer objections and decisions."
  });
  addCheck(aeo, {
    id: "faq_schema",
    label: "FAQ structured data",
    passed: schemaLower.includes("faqpage"),
    points: 1,
    severity: "low",
    success: "FAQ structured data was detected.",
    fail: "FAQ structured data was not detected.",
    action: "Add matching FAQ structured data where the visible content is eligible."
  });
  addCheck(aeo, {
    id: "extractable_formats",
    label: "Extractable lists and tables",
    passed: listCount + tableCount >= 3,
    points: 1,
    severity: "medium",
    success: "The page uses extractable lists or tables.",
    fail: "The page contains few extractable lists or tables.",
    action: "Use concise lists, steps, comparisons and tables where they aid understanding."
  });
  addCheck(aeo, {
    id: "concise_answers",
    label: "Concise answer paragraphs",
    passed: conciseAnswers >= 4,
    points: 1,
    severity: "medium",
    success: "Several concise answer-sized paragraphs are present.",
    fail: "The page contains too few concise answer-sized passages.",
    action: "Add clear 25-90 word answers supported by deeper detail."
  });
  addCheck(aeo, {
    id: "decision_topics",
    label: "Decision-topic coverage",
    passed: countPresent(lower, ["cost", "price", "process", "how long", "suitable", "included", "compare"]) >= 3,
    points: 2,
    severity: "high",
    success: "Multiple customer-decision topics are covered.",
    fail: "Important customer-decision topics are missing.",
    action: "Cover cost, process, timing, suitability, inclusions and comparisons."
  });
  addCheck(aeo, {
    id: "answer_depth",
    label: "Supporting answer depth",
    passed: wordCount >= 900,
    points: 1,
    severity: "medium",
    success: "The page contains enough depth to support its answers.",
    fail: "The page may lack enough depth to support direct answers.",
    action: "Support concise answers with evidence, examples and detailed explanation."
  });
  categories.aeo = createCategory("AEO & Google snippet readiness", 12, aeo);

  const geo = [];
  addCheck(geo, {
    id: "org_schema",
    label: "Organisation identity",
    passed: schemaLower.includes("organization") || schemaLower.includes("localbusiness"),
    points: 2,
    severity: "high",
    success: "Organisation identity is represented in structured data.",
    fail: "Organisation or LocalBusiness structured data was not detected.",
    action: "Add accurate organisation identity and contact facts in structured data."
  });
  addCheck(geo, {
    id: "service_schema",
    label: "Service or offer facts",
    passed: schemaLower.includes('"service"') || schemaLower.includes("servicetype") ||
      schemaLower.includes("product") || schemaLower.includes("offer"),
    points: 2,
    severity: "high",
    success: "Service, product or offer facts are structured.",
    fail: "Service, product or offer structured data was not detected.",
    action: "Structure the service or offer facts that match the visible page."
  });
  addCheck(geo, {
    id: "coverage_schema",
    label: "Coverage or market facts",
    passed: schemaLower.includes("areaserved") || schemaLower.includes("availableatorthrough"),
    points: 1,
    severity: "medium",
    success: "Coverage or availability facts are structured.",
    fail: "Coverage or availability facts are not clearly structured.",
    action: "Add accurate area-served or availability information where relevant."
  });
  addCheck(geo, {
    id: "about_contact",
    label: "Entity facts in visible content",
    passed: hasAny(lower, ["about us", "contact us", "our team", "our company", "founded", "based in", "serving"]),
    points: 1,
    severity: "medium",
    success: "Visible business facts help define the entity.",
    fail: "The page provides limited visible information about the business entity.",
    action: "Add clear company, service, coverage and contact facts."
  });
  addCheck(geo, {
    id: "author_publisher",
    label: "Author or publisher clarity",
    passed: schemaLower.includes("author") || schemaLower.includes("publisher") ||
      hasAny(lower, ["written by", "reviewed by", "our team"]),
    points: 1,
    severity: "medium",
    success: "Author or publisher information is available.",
    fail: "Author or publisher responsibility is unclear.",
    action: "Identify the responsible organisation or author where appropriate."
  });
  addCheck(geo, {
    id: "evidence",
    label: "Evidence supporting claims",
    passed: evidenceSignals(html, lower) >= 2,
    points: 2,
    severity: "high",
    success: "Multiple evidence signals support the page.",
    fail: "The page offers limited evidence supporting its claims.",
    action: "Add cases, reviews, examples, credentials and measurable outcomes."
  });
  addCheck(geo, {
    id: "same_as",
    label: "External identity references",
    passed: schemaLower.includes("sameas") || externalIdentityLinks(links) >= 1,
    points: 1,
    severity: "low",
    success: "External identity references are available.",
    fail: "No external identity references were detected.",
    action: "Connect genuine business profiles and authoritative identities where relevant."
  });
  addCheck(geo, {
    id: "source_network",
    label: "Connected source network",
    passed: supportingRouteCount(links) >= 3,
    points: 1,
    severity: "high",
    success: "The page is connected to supporting source pages.",
    fail: "The page lacks a strong network of supporting source pages.",
    action: "Connect services, locations, guides, evidence and company information."
  });
  addCheck(geo, {
    id: "specific_facts",
    label: "Specific extractable facts",
    passed: hasSpecificFacts(visible),
    points: 1,
    severity: "medium",
    success: "The page contains specific extractable facts.",
    fail: "The page contains few specific extractable facts.",
    action: "Add precise services, packages, timeframes, coverage and evidence."
  });
  categories.geo = createCategory("GEO & AI-source readiness", 12, geo);

  const trust = [];
  addCheck(trust, {
    id: "contact_link",
    label: "Clear enquiry route",
    passed: links.some(item => /contact|enquiry|quote|book|consultation/.test(item.href.toLowerCase())),
    points: 1,
    severity: "high",
    success: "A clear enquiry route is linked.",
    fail: "No clear contact, enquiry or quotation link was detected.",
    action: "Add a prominent and relevant enquiry route."
  });
  addCheck(trust, {
    id: "form",
    label: "Lead-capture form",
    passed: formCount >= 1,
    points: 1,
    severity: "medium",
    success: "A lead-capture form is available.",
    fail: "No lead-capture form was found on the page.",
    action: "Add an appropriate form or a clear link to one."
  });
  addCheck(trust, {
    id: "direct_contact",
    label: "Phone or email access",
    passed: phoneCount + emailCount >= 1 || hasAny(lower, ["telephone", "phone", "email us", "call us"]),
    points: 1,
    severity: "medium",
    success: "Direct contact information is available.",
    fail: "Direct phone or email access is limited.",
    action: "Make suitable direct contact options easy to find."
  });
  addCheck(trust, {
    id: "reviews",
    label: "Reviews or testimonials",
    passed: reviewEvidence(html, lower),
    points: 2,
    severity: "high",
    success: "Review or testimonial evidence is present.",
    fail: "No strong review or testimonial evidence was detected.",
    action: "Add genuine, detailed and attributable customer feedback."
  });
  addCheck(trust, {
    id: "case_studies",
    label: "Cases or portfolio evidence",
    passed: links.some(item => /case-stud|portfolio|project|our-work|results/.test(item.href.toLowerCase())) ||
      hasAny(lower, ["case study", "our work", "projects", "portfolio"]),
    points: 1,
    severity: "high",
    success: "Case-study or portfolio evidence is available.",
    fail: "No case-study or portfolio route was detected.",
    action: "Add relevant project examples and evidence of completed work."
  });
  addCheck(trust, {
    id: "pricing",
    label: "Pricing or package clarity",
    passed: hasAny(lower, ["pricing", "price", "package", "plans", "from GBP ", "from gbp", "quote"]),
    points: 1,
    severity: "medium",
    success: "Pricing, package or quotation guidance is visible.",
    fail: "Pricing, package or quotation guidance is unclear.",
    action: "Add proportionate pricing guidance, packages or quotation expectations."
  });
  addCheck(trust, {
    id: "legal",
    label: "Privacy and legal reassurance",
    passed: links.some(item => /privacy|terms|legal|cookies/.test(item.href.toLowerCase())),
    points: 1,
    severity: "medium",
    success: "Privacy or legal reassurance is linked.",
    fail: "Privacy or legal reassurance was not detected.",
    action: "Link clear privacy, terms and relevant policy information."
  });
  addCheck(trust, {
    id: "cta",
    label: "Strong calls to action",
    passed: buttonCount >= 2 || countPresent(lower, ["get started", "request", "book", "contact us", "get a quote", "buy now"]) >= 2,
    points: 1,
    severity: "high",
    success: "Multiple calls to action are present.",
    fail: "The page has weak or limited calls to action.",
    action: "Add clear next steps at suitable points in the customer journey."
  });
  addCheck(trust, {
    id: "expectations",
    label: "Process and expectation clarity",
    passed: hasAny(lower, ["how it works", "process", "what happens next", "included", "timeline", "guarantee", "not guaranteed", "terms"]),
    points: 1,
    severity: "medium",
    success: "The page explains process, inclusions or limitations.",
    fail: "The page provides limited process or expectation guidance.",
    action: "Explain the process, inclusions, limitations and what happens next."
  });
  categories.trust = createCategory("Trust, evidence & conversion", 10, trust);

  Object.values(categories).forEach(category => {
    category.checks.forEach(check => allChecks.push({ ...check, category: category.name }));
  });

  const overall = Math.round(
    Object.values(categories).reduce((sum, category) => sum + category.score, 0)
  );

  const groups = {
    foundation: groupScore("Search foundations", [
      categories.technical,
      categories.metadata,
      categories.performance,
      categories.architecture
    ]),
    relevance: groupScore("Content & market relevance", [
      categories.content,
      categories.commercial
    ]),
    answers: groupScore("Answer & AI readiness", [
      categories.aeo,
      categories.geo
    ]),
    conversion: groupScore("Trust & conversion", [
      categories.trust
    ])
  };

  const failed = allChecks.filter(check => !check.passed);
  const strengths = allChecks
    .filter(check => check.passed)
    .sort((a, b) => b.earned - a.earned)
    .slice(0, 6)
    .map(check => ({
      category: check.category,
      text: check.success
    }));

  const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
  const priorities = failed
    .sort((a, b) => {
      const severityDifference = severityRank[b.severity] - severityRank[a.severity];
      return severityDifference || b.points - a.points;
    })
    .slice(0, 6)
    .map(check => ({
      category: check.category,
      severity: check.severity,
      issue: check.fail,
      action: check.action,
      pointsAvailable: check.points
    }));

  const criticalIssues = failed.filter(item => item.severity === "critical").length;
  const highIssues = failed.filter(item => item.severity === "high").length;
  const target = 80;
  const targetAchieved = overall >= target && criticalIssues === 0;
  const pageStatus = criticalIssues > 0 ? "Critical blocker detected" :
    targetAchieved ? "Page-level target achieved" :
    overall >= 70 ? "Close to the page-level target" :
    overall >= 55 ? "Important page improvements recommended" :
    "Major page improvements required";

  const pageReadiness = {
    score: overall,
    target,
    targetAchieved,
    status: pageStatus,
    pointsToTarget: Math.max(0, target - overall),
    recoverablePagePoints: Math.max(0, 100 - overall),
    criticalIssues,
    highIssues
  };

  const sitewide = {
    status: "Not verified",
    seoHealth: "Not verified",
    searchCoverage: "Not verified",
    growthUnitWorkload: "Not calculated",
    note: "A strong individual page does not confirm that the wider website is technically healthy or covers enough services, locations, sectors, customer questions and evidence.",
    fullAuditChecks: [
      "Full-site technical and metadata crawl",
      "Duplicate titles, descriptions, pages and repeated content blocks",
      "Broken links, redirects, crawl depth and internal-link architecture",
      "Sitemap coverage, orphaned pages and sitemap-only URLs",
      "Keyword cannibalisation and competing pages",
      "Page-by-page content, AEO, GEO, trust and conversion review",
      "Validated missing-page and search-coverage map",
      "First-year and longer-term Growth Unit workload",
      "Prioritised 90-day build and proportionate package recommendation"
    ]
  };

  return {
    pageReadiness,
    overall,
    grade: gradeLabel(overall),
    groups,
    categories,
    strengths,
    priorities,
    sitewide,
    page: {
      title,
      metaDescription: description,
      canonical,
      robots: robotsMeta,
      wordCount,
      h1Count: h1.length,
      h2Count: h2.length,
      h3Count: h3.length,
      internalLinkCount: internalLinks.length,
      imageCount: images,
      imageAltCoverage: Math.round(altCoverage * 100),
      detectedLocation: location || null
    },
    pagespeed: pagespeed || { available: false },
    methodology: {
      scope: "Provisional single-page readiness audit with homepage, robots, sitemap and optional PageSpeed checks",
      targetScore: 80,
      rankingPrediction: false,
      fullSiteAuditCompleted: false,
      searchCoverageCalculated: false,
      growthUnitWorkloadCalculated: false,
      seobilityIncluded: false,
      searchConsoleIncluded: false,
      expertVerified: false,
      note: "This score assesses the entered page. It does not represent the complete website or predict an exact ranking position."
    }
  };
}

function createCategory(name, max, checks) {
  const earned = checks.reduce((sum, check) => sum + check.earned, 0);
  const possible = checks.reduce((sum, check) => sum + check.points, 0);
  const score = possible ? Math.round((earned / possible) * max) : 0;

  return {
    name,
    max,
    score,
    percentage: max ? Math.round((score / max) * 100) : 0,
    checks
  };
}

function addCheck(list, config) {
  const passed = Boolean(config.passed);
  list.push({
    ...config,
    passed,
    earned: passed ? config.points : 0,
    measured: true
  });
}

function addMetric(list, config) {
  let fraction = typeof config.fixedFraction === "number" ? config.fixedFraction : 0;
  let success = config.success || "";

  if (typeof config.fixedFraction !== "number") {
    for (const band of config.bands || []) {
      const matches = Object.prototype.hasOwnProperty.call(band, "equals")
        ? config.value === band.equals
        : typeof config.value === "number" && config.value >= band.min;

      if (matches) {
        fraction = band.fraction;
        success = band.success;
        break;
      }
    }
  }

  const earned = Math.round(config.points * fraction * 100) / 100;
  list.push({
    ...config,
    passed: fraction >= 0.7,
    earned,
    measured: config.value !== null,
    success,
    fail: config.fail
  });
}

function scoreBands() {
  return [
    { min: 90, fraction: 1, success: "The Lighthouse score is strong." },
    { min: 75, fraction: 0.75, success: "The Lighthouse score is reasonable." },
    { min: 50, fraction: 0.45, success: "The Lighthouse score needs improvement." },
    { min: 0, fraction: 0.15, success: "The Lighthouse score is weak." }
  ];
}

function groupScore(name, categories) {
  const score = categories.reduce((sum, category) => sum + category.score, 0);
  const max = categories.reduce((sum, category) => sum + category.max, 0);

  return {
    name,
    score,
    max,
    percentage: max ? Math.round((score / max) * 100) : 0
  };
}

function calculateConfidence(context) {
  let score = 35;
  const reasons = [];

  if (context.primary && context.primary.status >= 200 && context.primary.status < 400) {
    score += 10;
  } else {
    reasons.push("The target page response was incomplete.");
  }

  if (context.homepage && context.homepage.html) score += 8;
  else reasons.push("The homepage could not be checked.");

  if (context.robots && context.robots.ok) score += 7;
  else reasons.push("robots.txt could not be checked.");

  if (context.sitemap && context.sitemap.ok) score += 8;
  else reasons.push("A valid sitemap was not available.");

  if (context.pagespeed && context.pagespeed.available) score += 20;
  else reasons.push("PageSpeed data was unavailable.");

  if (context.wordCount >= 500) score += 5;
  else reasons.push("Limited visible content reduced confidence.");

  if (context.schema && context.schema.length > 20) score += 4;
  if (!context.jsShellLikely) score += 3;
  else reasons.push("The page may rely heavily on client-side rendering.");

  score = Math.min(100, score);

  return {
    score,
    label: score >= 85 ? "High" : score >= 65 ? "Good" : "Limited",
    reasons
  };
}

function recommendRoute(categories, overall, priorities) {
  const normalised = key => categories[key].percentage;
  const weakCount = Object.values(categories).filter(category => category.percentage < 60).length;

  let route = "Starter SEO";
  let reason = "The website has a workable foundation and would benefit from focused monthly improvements.";

  if (
    overall < 52 ||
    normalised("technical") < 55 ||
    normalised("metadata") < 50 ||
    normalised("performance") < 45
  ) {
    route = "Foundation Website";
    reason = "The website foundation needs improvement before broader growth work can perform consistently.";
  } else if (weakCount >= 4 || overall < 70) {
    route = "Growth";
    reason = "Several connected areas need to move forward together rather than through isolated fixes.";
  } else if (
    normalised("aeo") < 60 ||
    normalised("geo") < 60
  ) {
    route = "Starter SEO + AI Search";
    reason = "The core website is usable, but answer-led and AI-source clarity need focused development.";
  } else if (
    normalised("trust") < 60 &&
    normalised("technical") >= 65
  ) {
    route = "Website Conversion & AI Assistant";
    reason = "The site foundation is reasonable, but proof, enquiry routes and visitor handling need improvement.";
  }

  return {
    route,
    reason,
    firstActions: priorities.slice(0, 3).map(item => item.action)
  };
}

function gradeLabel(score) {
  if (score >= 90) return "Exceptional page readiness";
  if (score >= 80) return "Page-level target achieved";
  if (score >= 70) return "Close to target";
  if (score >= 55) return "Improvements recommended";
  return "Major improvements required";
}

function visibleText(html) {
  return decode(
    html
      .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
      .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
      .replace(/<noscript\b[\s\S]*?<\/noscript>/gi, " ")
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
  );
}

function decode(value) {
  return String(value || "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#(\d+);/g, (_, number) => String.fromCharCode(Number(number)))
    .replace(/\s+/g, " ")
    .trim();
}

function firstMatch(value, pattern) {
  const match = String(value || "").match(pattern);
  return match ? match[1] || "" : "";
}

function extractMeta(html, name) {
  const tags = html.match(/<meta\b[^>]*>/gi) || [];
  for (const tag of tags) {
    const metaName = attribute(tag, "name").toLowerCase();
    const property = attribute(tag, "property").toLowerCase();
    if (metaName === name.toLowerCase() || property === name.toLowerCase()) {
      return decode(attribute(tag, "content"));
    }
  }
  return "";
}

function extractLink(html, relName) {
  const tags = html.match(/<link\b[^>]*>/gi) || [];
  for (const tag of tags) {
    const rel = attribute(tag, "rel").toLowerCase().split(/\s+/);
    if (rel.includes(relName.toLowerCase())) return attribute(tag, "href");
  }
  return "";
}

function extractTags(html, tagName) {
  const pattern = new RegExp(`<${tagName}\\b[^>]*>([\\s\\S]*?)<\\/${tagName}>`, "gi");
  const values = [];
  let match;

  while ((match = pattern.exec(html)) !== null) {
    values.push(decode(match[1].replace(/<[^>]+>/g, " ")));
  }

  return values;
}

function extractAnchors(html, pageUrl) {
  const tags = html.match(/<a\b[^>]*>/gi) || [];
  const values = [];

  for (const tag of tags) {
    const href = attribute(tag, "href");
    const anchorText = decode(tag.replace(/<[^>]+>/g, " "));

    if (!href || href.startsWith("#") || href.toLowerCase().startsWith("javascript:")) continue;

    try {
      const parsed = new URL(href, pageUrl);
      values.push({
        href: parsed.href,
        internal: parsed.origin === pageUrl.origin,
        text: anchorText
      });
    } catch {}
  }

  return values;
}

function extractJsonLd(html) {
  const pattern = /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  const values = [];
  let match;

  while ((match = pattern.exec(html)) !== null) values.push(match[1]);
  return values.join(" ");
}

function attribute(tag, name) {
  const pattern = new RegExp(`${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i");
  const match = tag.match(pattern);
  return match ? decode(match[1] || match[2] || match[3] || "") : "";
}

function countMatches(value, pattern) {
  return (String(value || "").match(pattern) || []).length;
}

function countWords(value) {
  return String(value || "").split(/\s+/).filter(Boolean).length;
}

function hasAny(text, phrases) {
  return phrases.some(phrase => text.includes(phrase));
}

function countPresent(text, phrases) {
  return phrases.filter(phrase => text.includes(phrase)).length;
}

function countPhraseOccurrences(text, phrase) {
  return phrase ? text.split(phrase).length - 1 : 0;
}

function includesPhrase(text, phrase) {
  return String(text || "").toLowerCase().includes(String(phrase || "").toLowerCase());
}

function inferLocation(url, title, h1) {
  const pathMatch = url.pathname.match(
    /(?:seo-company|website-design|ai-search-optimisation)-([^/?#]+)$/i
  );
  if (pathMatch) return pathMatch[1].replace(/-/g, " ");

  const source = `${title} ${h1.join(" ")}`;
  const match = source.match(/\b(?:in|for)\s+([A-Z][A-Za-z' -]{2,40})(?:\||,|$)/);
  return match ? match[1].trim() : "";
}

function semanticOverlap(a, b) {
  const stop = new Set(["the", "and", "for", "with", "from", "your", "our", "a", "an", "of", "in"]);
  const left = new Set(tokenise(a).filter(word => !stop.has(word)));
  const right = new Set(tokenise(b).filter(word => !stop.has(word)));
  if (!left.size || !right.size) return 0;

  let shared = 0;
  left.forEach(word => {
    if (right.has(word)) shared += 1;
  });

  return shared / Math.max(left.size, right.size);
}

function tokenise(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .split(/\s+/)
    .filter(Boolean);
}

function headingHierarchyReasonable(html) {
  const headings = [];
  const pattern = /<(h[1-6])\b[^>]*>/gi;
  let match;

  while ((match = pattern.exec(html)) !== null) {
    headings.push(Number(match[1].slice(1)));
  }

  if (!headings.length) return false;
  let previous = headings[0];

  for (const level of headings.slice(1)) {
    if (level - previous > 1) return false;
    previous = level;
  }

  return true;
}

function hasSpecificFacts(text) {
  const numberFacts = (String(text || "").match(/\b(?:\d{1,4}|GBP \s?\d+|GBP\s?\d+|\d+%)\b/g) || []).length;
  const namedItems = countPresent(String(text || "").toLowerCase(), [
    "starter", "foundation", "growth", "scale", "included", "working days", "monthly", "years"
  ]);
  return numberFacts >= 2 || namedItems >= 2;
}

function evidenceSignals(html, lowerText) {
  let score = 0;
  if (reviewEvidence(html, lowerText)) score += 1;
  if (hasAny(lowerText, ["case study", "portfolio", "our work", "project example", "results"])) score += 1;
  if (hasAny(lowerText, ["qualified", "accredited", "certified", "years experience", "experience"])) score += 1;
  if (hasAny(lowerText, ["before and after", "measured", "increase", "improved", "saved"])) score += 1;
  return score;
}

function reviewEvidence(html, lowerText) {
  return (
    /itemprop\s*=\s*["']review/i.test(html) ||
    /"@type"\s*:\s*"Review"/i.test(html) ||
    countMatches(html, /<blockquote\b/gi) >= 1 ||
    countPresent(lowerText, ["testimonial", "customer review", "client review", "five star", "5 star"]) >= 1
  );
}

function anchorQualityRatio(links) {
  if (!links.length) return 0;
  const generic = new Set([
    "", "click here", "learn more", "read more", "here", "more", "view", "details", "link"
  ]);
  const useful = links.filter(link => {
    const text = String(link.text || "").toLowerCase().trim();
    return text.length >= 4 && !generic.has(text);
  }).length;

  return useful / links.length;
}

function supportingRouteCount(links) {
  const patterns = [
    /service|product|package|pricing/,
    /location|area|city|county|seo-company|website-design|ai-search/,
    /guide|blog|article|resource|faq/,
    /case-stud|portfolio|project|review|testimonial/,
    /contact|enquiry|quote|book/
  ];

  return patterns.filter(pattern =>
    links.some(link => pattern.test(link.href.toLowerCase()))
  ).length;
}

function externalIdentityLinks(links) {
  const patterns = [
    /linkedin\.com/,
    /facebook\.com/,
    /instagram\.com/,
    /youtube\.com/,
    /x\.com/,
    /twitter\.com/,
    /google\.com\/maps/,
    /trustpilot\.com/
  ];

  return links.filter(link =>
    !link.internal && patterns.some(pattern => pattern.test(link.href.toLowerCase()))
  ).length;
}

function topicClarity(firstText, title, h1) {
  const source = `${title} ${h1.join(" ")}`;
  const important = tokenise(source).filter(word => word.length >= 4);
  if (!important.length) return false;

  const hits = important.filter(word => firstText.includes(word)).length;
  return hits >= Math.min(3, important.length);
}


function mrbrandsToolResponse() {
  return new Response(MRBRANDS_TOOL_HTML, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": "frame-ancestors https://mrbrands.store https://www.mrbrands.store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin"
    }
  });
}

const MRBRANDS_TOOL_HTML = '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>MrBrands Instant Page Readiness Score</title>\n<style>\n:root{--l:#d3f208;--l2:#ecff59;--i:#15170f;--m:#707565;--s:#f7fae8;--ln:#dfe5c3}\n*{box-sizing:border-box}\nhtml{scroll-behavior:smooth}\nbody{margin:0;color:var(--i);background:#050505;font-family:Arial,sans-serif}\nbutton,input{font:inherit}\n.wrap{width:min(930px,calc(100% - 26px));margin:auto}\n.hero{padding:34px 0 28px;color:#fff;background:radial-gradient(circle at 90% 8%,rgba(211,242,8,.19),transparent 35%),linear-gradient(135deg,#030303,#151608)}\n.k{display:flex;align-items:center;gap:8px;margin-bottom:12px;color:var(--l);font-size:10px;font-weight:900;letter-spacing:.1em;text-transform:uppercase}\n.k:before{content:"";width:25px;height:3px;border-radius:9px;background:var(--l)}\nh1{margin:0 0 14px;font-size:clamp(34px,7vw,57px);line-height:1;letter-spacing:-.045em}\nh1 span{color:var(--l)}\n.lead{margin:0;color:rgba(255,255,255,.77);font-size:15px;line-height:1.65}\n.form{display:grid;grid-template-columns:1fr auto;gap:9px;margin-top:21px}\n.input{min-height:53px;padding:13px 16px;border:1px solid rgba(211,242,8,.35);border-radius:999px;background:#fff;color:#111;outline:none}\n.button{min-height:53px;padding:13px 20px;border:0;border-radius:999px;background:var(--l);color:#050505;font-weight:900;cursor:pointer}\n.button:disabled{opacity:.65;cursor:wait}\n.small{margin:9px 0 0;color:rgba(255,255,255,.55);font-size:10px;line-height:1.5}\n.progress{margin-top:18px;padding:17px;border:1px solid rgba(211,242,8,.28);border-radius:18px;background:rgba(255,255,255,.055)}\n.phead{display:grid;grid-template-columns:34px 1fr auto;gap:11px;align-items:center}\n.spin{width:32px;height:32px;border:3px solid rgba(255,255,255,.15);border-top-color:var(--l);border-radius:50%}\n.running .spin{animation:spin .8s linear infinite}\n.done .spin,.online .spin{border:0;background:var(--l)}\n.done .spin:after,.online .spin:after{content:"✓";display:flex;width:32px;height:32px;align-items:center;justify-content:center;color:#050505;font-size:17px;font-weight:900}\n.error .spin{border:0;background:#ffd17a}\n.error .spin:after{content:"!";display:flex;width:32px;height:32px;align-items:center;justify-content:center;color:#472500;font-size:17px;font-weight:900}\n@keyframes spin{to{transform:rotate(360deg)}}\n.ptitle{display:block;color:#fff;font-size:13px;font-weight:900}\n.ptime{display:block;margin-top:3px;color:rgba(255,255,255,.54);font-size:9px}\n.percent{color:var(--l);font-size:14px;font-weight:900}\n.track{height:9px;margin-top:13px;border-radius:999px;background:rgba(255,255,255,.1);overflow:hidden}\n.fill{display:block;width:2%;height:100%;border-radius:999px;background:linear-gradient(90deg,var(--l),var(--l2));transition:width .55s ease}\n.current{margin-top:11px;color:rgba(255,255,255,.82);font-size:11px;line-height:1.5}\n.note{margin-top:4px;color:rgba(255,255,255,.5);font-size:9px;line-height:1.45}\n.steps{display:grid;grid-template-columns:repeat(2,1fr);gap:6px;margin:12px 0 0;padding:0;list-style:none}\n.steps li{position:relative;padding:8px 8px 8px 26px;border:1px solid rgba(255,255,255,.07);border-radius:10px;color:rgba(255,255,255,.43);font-size:9px;line-height:1.35}\n.steps li:before{content:"";position:absolute;left:9px;top:50%;width:7px;height:7px;border:1px solid rgba(255,255,255,.28);border-radius:50%;transform:translateY(-50%)}\n.steps li.active{border-color:rgba(211,242,8,.28);color:#fff;background:rgba(211,242,8,.06)}\n.steps li.active:before{border-color:var(--l);background:var(--l)}\n.steps li.done-step{color:rgba(255,255,255,.7)}\n.steps li.done-step:before{content:"✓";display:flex;width:13px;height:13px;left:6px;align-items:center;justify-content:center;border:0;color:var(--l);font-size:9px;font-weight:900}\n.results{display:none;padding:28px 0 40px;background:var(--s)}\n.results.show{display:block}\n.scoregrid{display:grid;grid-template-columns:245px 1fr;gap:17px}\n.overall{padding:22px;border-radius:20px;color:#fff;background:linear-gradient(135deg,#030303,#151608)}\n.overall small{display:block;color:var(--l);font-size:9px;font-weight:900;letter-spacing:.08em;text-transform:uppercase}\n.score{margin-top:8px;font-size:65px;line-height:.9;font-weight:900;letter-spacing:-.06em}\n.score em{font-size:20px;color:rgba(255,255,255,.45);font-style:normal}\n.target{display:inline-block;margin-top:13px;padding:7px 10px;border:1px solid rgba(211,242,8,.2);border-radius:999px;color:var(--l);font-size:10px;font-weight:900}\n.grade{margin-top:13px;color:#fff;font-size:17px;font-weight:900}\n.copy{margin-top:7px;color:rgba(255,255,255,.65);font-size:10px;line-height:1.55}\n.groups{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}\n.group{padding:16px;border:1px solid var(--ln);border-radius:15px;background:#fff}\n.ghead{display:flex;justify-content:space-between;gap:10px;font-size:11px;font-weight:900}\n.bar{height:8px;margin-top:9px;border-radius:999px;background:#edf1dc;overflow:hidden}\n.bar span{display:block;height:100%;background:var(--l)}\n.group p{margin:8px 0 0;color:var(--m);font-size:9px}\n.priorities{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:18px}\n.priority{padding:15px;border:1px solid var(--ln);border-radius:15px;background:#fff}\n.priority small{color:#7a8900;font-size:8px;font-weight:900;text-transform:uppercase}\n.priority b{display:block;margin:7px 0;color:var(--i);font-size:12px;line-height:1.35}\n.priority p{margin:0;color:var(--m);font-size:9px;line-height:1.5}\n.action{margin-top:8px;padding-top:8px;border-top:1px solid var(--ln);color:#3f482a;font-size:9px;line-height:1.5}\n.next{margin-top:18px;padding:18px;border:1px solid #d6e490;border-radius:17px;background:#f3ffc2}\n.next b{display:block;font-size:17px;line-height:1.25}\n.next p{margin:7px 0 12px;color:#505a31;font-size:10px;line-height:1.55}\n.next a{display:inline-flex;padding:11px 16px;border-radius:999px;background:#050505;color:#fff;font-size:10px;font-weight:900;text-decoration:none}\n@media(max-width:690px){.form,.scoregrid{grid-template-columns:1fr}.button{width:100%}.steps,.groups,.priorities{grid-template-columns:1fr}.hero{padding-top:27px}}\n</style>\n</head>\n<body>\n<section class="hero">\n<div class="wrap">\n<div class="k">Instant Page Readiness Score</div>\n<h1>How well is this page prepared to <span>rank, answer and convert?</span></h1>\n<p class="lead">Enter any public webpage. The live audit checks this page across technical access, metadata, mobile performance, content, internal discovery, market relevance, AEO, GEO, trust and conversion.</p>\n<div class="form">\n<input class="input" id="url" type="url" inputmode="url" placeholder="https://example.com">\n<button class="button" id="run" type="button">Run the page readiness score</button>\n</div>\n<p class="small">Target score: 80+. Typical audit time: 20-35 seconds. Maximum wait: 90 seconds.</p>\n<div class="progress" id="progress" aria-live="polite">\n<div class="phead"><span class="spin"></span><div><span class="ptitle" id="ptitle">Audit engine online - ready to run</span><span class="ptime" id="ptime">Enter a URL above to begin</span></div><span class="percent" id="percent">Ready</span></div>\n<div class="track"><span class="fill" id="fill" style="width:100%"></span></div>\n<div class="current" id="current">The timer and stages begin immediately when you press the button.</div>\n<div class="note" id="note">The full-site audit is separate because one page cannot reveal sitewide duplication, architecture or page-volume opportunity.</div>\n<ul class="steps" id="steps">\n<li data-step="0">Secure connection</li><li data-step="1">Fetch submitted page</li>\n<li data-step="2">Technical and metadata</li><li data-step="3">Homepage, robots and sitemap</li>\n<li data-step="4">Mobile PageSpeed</li><li data-step="5">Content, AEO and GEO</li>\n<li data-step="6">Trust and conversion</li><li data-step="7">Compile results</li>\n</ul>\n</div>\n</div>\n</section>\n<section class="results" id="results">\n<div class="wrap">\n<div class="scoregrid">\n<aside class="overall"><small>Provisional page readiness</small><div class="score"><span id="overall">0</span><em>/100</em></div><div class="target">Target: 80+</div><div class="grade" id="grade"></div><p class="copy" id="copy"></p></aside>\n<div class="groups" id="groups"></div>\n</div>\n<div class="priorities" id="priorities"></div>\n<div class="next"><b>A strong page is only the first stage.</b><p>Verify the whole website to calculate Sitewide SEO Health, Search Coverage, missing page opportunities and the validated Growth Unit workload.</p><a id="audit" href="https://mrbrands.store/pages/local-growth-map" target="_top">Map My Full Website Opportunity →</a></div>\n</div>\n</section>\n<script>\n(function(){\nconst plan=[\n[0,4,"Starting the secure audit","Connecting to the MrBrands audit engine."],\n[2,12,"Fetching the submitted page","Following redirects and reading the live HTML."],\n[5,25,"Checking technical foundations","Reviewing indexability, metadata, headings and canonicals."],\n[9,39,"Reviewing content and structure","Checking copy, links, schema and market relevance."],\n[13,53,"Checking wider website signals","Reviewing the homepage, robots.txt and XML sitemap."],\n[17,67,"Running mobile performance","Requesting PageSpeed data where available."],\n[25,80,"Scoring AEO, GEO and trust","Assessing answers, AI-source clarity and conversion."],\n[34,90,"Compiling the final result","Prioritising issues and preparing the report."],\n[48,94,"Still working on a slower response","The site or PageSpeed service is taking longer than usual."]\n];\nlet timer=null,start=0;\nconst e=id=>document.getElementById(id);\nfunction valid(v){try{let x=v.trim();if(!/^https?:\\/\\//i.test(x))x="https://"+x;return new URL(x)}catch{return null}}\nfunction stage(n){document.querySelectorAll(".steps li").forEach((li,i)=>{li.classList.toggle("done-step",i<n);li.classList.toggle("active",i===n)})}\nfunction tick(){\nconst seconds=Math.floor((Date.now()-start)/1000);let index=0;\nfor(let i=0;i<plan.length;i++)if(seconds>=plan[i][0])index=i;\nconst p=plan[index],next=plan[Math.min(index+1,plan.length-1)];\nlet percent=p[1];\nif(next[0]>p[0])percent=Math.min(94,Math.round(p[1]+(next[1]-p[1])*Math.min(1,(seconds-p[0])/(next[0]-p[0]))));\ne("ptitle").textContent=p[2];e("current").textContent=p[3];e("ptime").textContent=seconds+" second"+(seconds===1?"":"s")+" elapsed";e("percent").textContent=percent+"%";e("fill").style.width=percent+"%";e("run").textContent="Running... "+seconds+"s";stage(Math.min(index,7));\n}\nfunction startProgress(){const box=e("progress");box.className="progress running";start=Date.now();stage(0);tick();clearInterval(timer);timer=setInterval(tick,500);box.scrollIntoView({behavior:"smooth",block:"center"})}\nfunction finish(){clearInterval(timer);const seconds=Math.floor((Date.now()-start)/1000),box=e("progress");box.className="progress done";e("ptitle").textContent="Audit completed";e("ptime").textContent=seconds+" seconds total";e("percent").textContent="100%";e("fill").style.width="100%";e("current").textContent="Your score and priority findings are ready below.";document.querySelectorAll(".steps li").forEach(li=>{li.classList.remove("active");li.classList.add("done-step")})}\nfunction fail(message){clearInterval(timer);const box=e("progress");box.className="progress error";e("ptitle").textContent="The audit could not finish";e("ptime").textContent=Math.floor((Date.now()-start)/1000)+" seconds elapsed";e("percent").textContent="Stopped";e("fill").style.width="100%";e("current").textContent=message}\nfunction render(r,url){\ne("overall").textContent=r.pageReadiness.score;e("grade").textContent=r.pageReadiness.status;\ne("copy").textContent=r.pageReadiness.targetAchieved?"This page has achieved the 80+ target. The full-site audit should now verify wider health and market coverage.":r.pageReadiness.pointsToTarget+" points remain to reach the page-level target.";\ne("groups").innerHTML=Object.values(r.groups).map(g=>\'<article class="group"><div class="ghead"><span>\'+g.name+\'</span><span>\'+g.score+\'/\'+g.max+\'</span></div><div class="bar"><span style="width:\'+g.percentage+\'%"></span></div><p>\'+(g.percentage>=80?"Strong":g.percentage>=65?"Developing":"Priority area")+\'</p></article>\').join("");\ne("priorities").innerHTML=r.priorities.slice(0,3).map(p=>\'<article class="priority"><small>\'+p.severity+\' priority</small><b>\'+p.issue+\'</b><p>\'+p.category+\'</p><div class="action"><strong>Action:</strong> \'+p.action+\'</div></article>\').join("")||\'<article class="priority"><b>No major page-level issues detected.</b><p>Proceed to the full-site audit to verify architecture, duplication and coverage.</p></article>\';\ne("audit").href="https://mrbrands.store/pages/local-growth-map?website="+encodeURIComponent(url.href)+"&instant_score="+encodeURIComponent(r.pageReadiness.score)+"&page_status="+encodeURIComponent(r.pageReadiness.status);\ne("results").classList.add("show");e("results").scrollIntoView({behavior:"smooth",block:"start"});\n}\nasync function run(){\nconst url=valid(e("url").value);if(!url){fail("Enter a valid public webpage URL.");return}\ne("run").disabled=true;startProgress();await new Promise(r=>setTimeout(r,100));\nconst controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),90000);\ntry{\nconst response=await fetch("/audit",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:url.href}),signal:controller.signal});\nconst payload=await response.json();if(!response.ok||!payload.ok)throw new Error(payload.error||"The page could not be audited.");\nfinish();render(payload.result,url);\n}catch(error){fail(error.name==="AbortError"?"The audit exceeded 90 seconds. The website or PageSpeed service may be responding too slowly.":"The audit could not be completed: "+error.message)}\nfinally{clearTimeout(timeout);e("run").disabled=false;e("run").textContent="Run the page readiness score"}\n}\ne("run").addEventListener("click",run);e("url").addEventListener("keydown",event=>{if(event.key==="Enter"){event.preventDefault();run()}});\n})();\n</script>\n</body>\n</html>';
