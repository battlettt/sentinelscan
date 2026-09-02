export interface FixSnippet {
  express: string;
  nginx: string;
}

const SNIPPETS: Record<string, FixSnippet> = {
  'missing-csp': {
    express: `app.use((req, res, next) => {\n  res.setHeader("Content-Security-Policy", "default-src 'self'");\n  next();\n});`,
    nginx: `add_header Content-Security-Policy "default-src 'self'" always;`,
  },
  'weak-csp': {
    express: `app.use((req, res, next) => {\n  res.setHeader("Content-Security-Policy", "default-src 'self'"); // drop unsafe-inline/unsafe-eval\n  next();\n});`,
    nginx: `add_header Content-Security-Policy "default-src 'self'" always; # drop unsafe-inline/unsafe-eval`,
  },
  'missing-hsts': {
    express: `app.use((req, res, next) => {\n  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");\n  next();\n});`,
    nginx: `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;`,
  },
  'missing-frame-protection': {
    express: `app.use((req, res, next) => {\n  res.setHeader("X-Frame-Options", "DENY");\n  next();\n});`,
    nginx: `add_header X-Frame-Options "DENY" always;`,
  },
  'missing-content-type-options': {
    express: `app.use((req, res, next) => {\n  res.setHeader("X-Content-Type-Options", "nosniff");\n  next();\n});`,
    nginx: `add_header X-Content-Type-Options "nosniff" always;`,
  },
  'missing-referrer-policy': {
    express: `app.use((req, res, next) => {\n  res.setHeader("Referrer-Policy", "no-referrer");\n  next();\n});`,
    nginx: `add_header Referrer-Policy "no-referrer" always;`,
  },
  'missing-permissions-policy': {
    express: `app.use((req, res, next) => {\n  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");\n  next();\n});`,
    nginx: `add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;`,
  },
};

export function getFixSnippet(findingId: string): FixSnippet | undefined {
  return SNIPPETS[findingId];
}
