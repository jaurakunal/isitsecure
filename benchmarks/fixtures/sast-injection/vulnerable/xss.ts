// Injection benchmark fixture — reflected & DOM XSS (VULNERABLE).

// --- Reflected XSS: request data → HTML response without escaping ---
export async function reflected(req: Request) {
  const url = new URL(req.url);
  const q = url.searchParams.get("q");
  const html = `<h1>Results for ${q}</h1>`;
  return new Response(html, { headers: { "content-type": "text/html" } }); // EXPECT reflected-xss
}

// --- Reflected XSS via res.send (Express shape) ---
export function expressReflect(req: any, res: any) {
  const name = req.query.name;
  res.send(`<p>Hello ${name}</p>`); // EXPECT reflected-xss
}

// --- DOM XSS: location.hash → innerHTML ---
export function renderFromHash(el: HTMLElement) {
  const data = window.location.hash;
  el.innerHTML = data; // EXPECT dom-xss
}

// --- DOM XSS: location.search → document.write ---
export function writeFromSearch() {
  document.write(window.location.search); // EXPECT dom-xss
}
